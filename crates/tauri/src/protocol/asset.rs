// Copyright 2019-2024 Tauri Programme within The Commons Conservancy
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

use crate::{path::SafePathBuf, scope, webview::UriSchemeProtocolHandler};
use http::{Request, Response, header::*, status::StatusCode};
use http_range::HttpRange;
use std::{borrow::Cow, io::SeekFrom};
use tauri_utils::mime_type::MimeType;
use std::fs::File;
use std::io::{Read, Seek, Write};

pub fn get(scope: scope::fs::Scope, window_origin: String) -> UriSchemeProtocolHandler {
  Box::new(move |_, request, responder| {
    let scope = scope.clone();
    let window_origin = window_origin.clone();
    // One blocking hop per request: the scope check (which canonicalizes), the open, the size
    // and the read are all file system calls, and each async step was its own pool hop.
    crate::async_runtime::spawn_blocking(move || {
      match get_response(request, &scope, &window_origin) {
        Ok(response) => responder.respond(response),
        Err(e) => responder.respond(
          http::Response::builder()
            .status(http::StatusCode::INTERNAL_SERVER_ERROR)
            .header(CONTENT_TYPE, mime::TEXT_PLAIN.essence_str())
            .header("Access-Control-Allow-Origin", &window_origin)
            .body(e.to_string().into_bytes())
            .unwrap(),
        ),
      }
    });
  })
}

/// Bytes sniffed for the MIME type.
const SNIFF_LEN: u64 = 8192;

fn get_response(
  request: Request<Vec<u8>>,
  scope: &scope::fs::Scope,
  window_origin: &str,
) -> Result<Response<Cow<'static, [u8]>>, Box<dyn std::error::Error>> {
  // skip leading `/`
  let path = request.uri().path().as_bytes();
  let path =
    percent_encoding::percent_decode(path.strip_prefix(b"/").unwrap_or(path)).decode_utf8_lossy();

  let mut resp = Response::builder().header("Access-Control-Allow-Origin", window_origin);

  let safe_path = match SafePathBuf::new(path.as_ref().into()) {
    Ok(path) => path,
    Err(e) => {
      log::error!("asset protocol path \"{path}\" is not valid: {e}");
      return resp.status(403).body(Vec::new().into()).map_err(Into::into);
    }
  };

  if !scope.is_allowed(&safe_path) {
    log::error!("asset protocol not configured to allow the path: {path}");
    return resp.status(403).body(Vec::new().into()).map_err(Into::into);
  }

  // Separate block for easier error handling
  let mut file = match File::open(&safe_path) {
    Ok(file) => file,
    Err(e) => {
      #[cfg(target_os = "android")]
      {
        if path.starts_with("/storage/emulated/0/Android/data/") {
          log::error!(
            "Failed to open Android external storage file '{path}': {e}. This may be due to missing storage permissions."
          );
        }
      }
      return if e.kind() == std::io::ErrorKind::NotFound {
        log::error!("File does not exist at path: {path}");
        return resp.status(404).body(Vec::new().into()).map_err(Into::into);
      } else if e.kind() == std::io::ErrorKind::PermissionDenied {
        log::error!("Missing OS permission to access path \"{path}\": {e}");
        return resp.status(403).body(Vec::new().into()).map_err(Into::into);
      } else {
        Err(e.into())
      };
    }
  };

  let len = file.metadata()?.len();
  let range_header = request
    .headers()
    .get("range")
    .and_then(|r| r.to_str().ok());

  // A whole-file GET reads the file once and sniffs its head from that read; a range or HEAD
  // request reads only the head.
  let whole = range_header.is_none() && request.method() != http::Method::HEAD;
  let (mime_type, body) = if whole {
    let mut buf = Vec::with_capacity(len as usize);
    file.read_to_end(&mut buf)?;
    let head = &buf[..buf.len().min(SNIFF_LEN as usize)];
    (MimeType::parse(head, &path), Some(buf))
  } else {
    let mut head = Vec::with_capacity(len.min(SNIFF_LEN) as usize);
    (&mut file).take(SNIFF_LEN).read_to_end(&mut head)?;
    (MimeType::parse(&head, &path), None)
  };

  resp = resp.header(CONTENT_TYPE, &mime_type);

  if let Some(buf) = body {
    resp = resp.header(CONTENT_LENGTH, buf.len());
    return resp.body(buf.into()).map_err(Into::into);
  }

  let Some(range_header) = range_header else {
    // HEAD: no body
    resp = resp.header(CONTENT_LENGTH, len);
    return resp.body(Vec::new().into()).map_err(Into::into);
  };

  // handle 206 (partial range) http requests
  resp = resp.header(ACCEPT_RANGES, "bytes");
  resp = resp.header(ACCESS_CONTROL_EXPOSE_HEADERS, "content-range");

  let not_satisfiable = || {
    Response::builder()
      .status(StatusCode::RANGE_NOT_SATISFIABLE)
      .header(CONTENT_RANGE, format!("bytes */{len}"))
      .body(vec![].into())
      .map_err(Into::into)
  };

  // parse range header
  let ranges = if let Ok(ranges) = HttpRange::parse(range_header, len) {
    ranges
      .iter()
      // map the output to spec range <start-end>, example: 0-499
      .map(|r| (r.start, r.start + r.length - 1))
      .collect::<Vec<_>>()
  } else {
    return not_satisfiable();
  };

  /// The Maximum bytes we send in one range
  const MAX_LEN: u64 = 1000 * 1024;

  // single-part range header
  if ranges.len() == 1 {
    let &(start, mut end) = ranges.first().unwrap();

    // check if a range is not satisfiable
    //
    // this should be already taken care of by the range parsing library
    // but checking here again for extra assurance
    if start >= len || end >= len || end < start {
      return not_satisfiable();
    }

    // adjust end byte for MAX_LEN
    end = start + (end - start).min(len - start).min(MAX_LEN - 1);

    // calculate number of bytes needed to be read
    let nbytes = end + 1 - start;

    let mut buf = Vec::with_capacity(nbytes as usize);
    file.seek(SeekFrom::Start(start))?;
    file.take(nbytes).read_to_end(&mut buf)?;

    resp = resp.header(CONTENT_RANGE, format!("bytes {start}-{end}/{len}"));
    resp = resp.header(CONTENT_LENGTH, end + 1 - start);
    resp = resp.status(StatusCode::PARTIAL_CONTENT);
    resp.body(buf.into()).map_err(Into::into)
  } else {
    let ranges = ranges
      .iter()
      .filter_map(|&(start, mut end)| {
        // filter out unsatisfiable ranges
        //
        // this should be already taken care of by the range parsing library
        // but checking here again for extra assurance
        if start >= len || end >= len || end < start {
          None
        } else {
          // adjust end byte for MAX_LEN
          end = start + (end - start).min(len - start).min(MAX_LEN - 1);
          Some((start, end))
        }
      })
      .collect::<Vec<_>>();

    let boundary = random_boundary();
    let boundary_sep = format!("\r\n--{boundary}\r\n");
    let boundary_closer = format!("\r\n--{boundary}--\r\n");

    // `Builder::header` appends, we want to replace the file mime type set earlier
    if let Some(headers) = resp.headers_mut() {
      headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_str(&format!("multipart/byteranges; boundary={boundary}"))?,
      );
    }

    // multi-part range header
    let mut buf = Vec::new();

    for (start, end) in ranges {
      // a new range is being written, write the range boundary
      buf.write_all(boundary_sep.as_bytes())?;

      // write the needed headers `Content-Type` and `Content-Range`
      buf.write_all(format!("{CONTENT_TYPE}: {mime_type}\r\n").as_bytes())?;
      buf.write_all(format!("{CONTENT_RANGE}: bytes {start}-{end}/{len}\r\n").as_bytes())?;

      // write the separator to indicate the start of the range body
      buf.write_all("\r\n".as_bytes())?;

      // calculate number of bytes needed to be read
      let nbytes = end + 1 - start;

      buf.reserve(nbytes as usize);
      file.seek(SeekFrom::Start(start))?;
      (&mut file).take(nbytes).read_to_end(&mut buf)?;
    }
    // all ranges have been written, write the closing boundary
    buf.write_all(boundary_closer.as_bytes())?;

    resp = resp.status(StatusCode::PARTIAL_CONTENT);
    resp.body(buf.into()).map_err(Into::into)
  }
}

fn random_boundary() -> String {
  let mut x = [0_u8; 30];
  getrandom::fill(&mut x).expect("failed to get random bytes");
  (x[..])
    .iter()
    .map(|&x| format!("{x:x}"))
    .fold(String::new(), |mut a, x| {
      a.push_str(x.as_str());
      a
    })
}

#[cfg(test)]
mod tests {
  use super::get_response;
  use crate::scope::fs::Scope;
  use http::{Request, header::CONTENT_TYPE, status::StatusCode};
  use tauri_utils::config::FsScope;

  #[test]
  fn multi_range_request() {
    let app = crate::test::mock_app();

    let path = std::env::temp_dir().join(format!(
      "tauri-asset-protocol-multi-range-{}.bin",
      std::process::id()
    ));
    std::fs::write(&path, vec![b'a'; 1000]).unwrap();

    let scope = Scope::new(&app, &FsScope::default()).unwrap();
    scope.allow_file(&path).unwrap();

    let encoded_path = percent_encoding::percent_encode(
      path.to_string_lossy().as_bytes(),
      percent_encoding::NON_ALPHANUMERIC,
    )
    .to_string();

    let request = Request::builder()
      .uri(format!("asset://localhost/{encoded_path}"))
      .header("range", "bytes=0-9, 20-29")
      .body(Vec::new())
      .unwrap();

    let response =
      get_response(request, &scope, "http://tauri.localhost")
        .unwrap();
    std::fs::remove_file(&path).unwrap();

    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);

    let content_types = response
      .headers()
      .get_all(CONTENT_TYPE)
      .iter()
      .map(|v| v.to_str().unwrap().to_string())
      .collect::<Vec<_>>();
    assert_eq!(content_types.len(), 1);

    let boundary = content_types[0]
      .strip_prefix("multipart/byteranges; boundary=")
      .unwrap();
    assert!(
      response
        .body()
        .ends_with(format!("\r\n--{boundary}--\r\n").as_bytes())
    );
  }

  #[test]
  fn empty_path_request() {
    let app = crate::test::mock_app();

    let scope = Scope::new(&app, &FsScope::default()).unwrap();

    // `asset:foo` parses as authority-form, so its path is empty;
    // this used to panic when stripping the leading `/`
    let uri = http::Uri::from_static("asset:foo");
    assert_eq!(uri.path(), "");

    let request = Request::builder().uri(uri).body(Vec::new()).unwrap();

    let response =
      get_response(request, &scope, "http://tauri.localhost")
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
  }
}

#[cfg(test)]
mod bench {
  //! `cargo test -p tauri --release --lib protocol::asset::bench -- --ignored --nocapture`
  use super::get_response;
  use crate::scope::fs::Scope;
  use http::Request;
  use tauri_utils::config::FsScope;

  /// The handler as it was: async steps, the head read twice.
  async fn old_get_response(path: &std::path::Path, scope: &Scope) -> usize {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    assert!(scope.is_allowed(path));
    let mut file = tokio::fs::File::open(path).await.unwrap();
    let len = file.metadata().await.unwrap().len();
    let mut magic = Vec::with_capacity(len.min(8192) as usize);
    (&mut file).take(8192).read_to_end(&mut magic).await.unwrap();
    file.rewind().await.unwrap();
    let mut buf = Vec::with_capacity(len as usize);
    file.read_to_end(&mut buf).await.unwrap();
    buf.len()
  }

  #[test]
  #[ignore]
  fn asset_requests() {
    let app = crate::test::mock_app();
    let path = std::env::temp_dir().join(format!("tauri-asset-bench-{}.png", std::process::id()));
    std::fs::write(&path, vec![7u8; 48 * 1024]).unwrap();
    let scope = Scope::new(&app, &FsScope::default()).unwrap();
    scope.allow_file(&path).unwrap();
    let encoded = percent_encoding::percent_encode(path.to_string_lossy().as_bytes(), percent_encoding::NON_ALPHANUMERIC).to_string();
    const N: usize = 3000;
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();

    let t = std::time::Instant::now();
    rt.block_on(async {
      for _ in 0..N {
        old_get_response(&path, &scope).await;
      }
    });
    let old = t.elapsed();

    let t = std::time::Instant::now();
    rt.block_on(async {
      for _ in 0..N {
        let request = Request::builder().uri(format!("asset://localhost/{encoded}")).body(Vec::new()).unwrap();
        let scope = scope.clone();
        tokio::task::spawn_blocking(move || get_response(request, &scope, "http://tauri.localhost").unwrap())
          .await
          .unwrap();
      }
    });
    let new = t.elapsed();
    std::fs::remove_file(&path).unwrap();
    println!("48 KiB asset x{N}: old {:.1} us/req, new {:.1} us/req", old.as_secs_f64() * 1e6 / N as f64, new.as_secs_f64() * 1e6 / N as f64);
  }
}
