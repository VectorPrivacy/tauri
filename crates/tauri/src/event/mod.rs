// Copyright 2019-2024 Tauri Programme within The Commons Conservancy
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

mod listener;
pub(crate) mod plugin;
use std::{convert::Infallible, str::FromStr};

pub(crate) use listener::Listeners;
use serde::{Deserialize, Serialize};

mod event_name;

pub(crate) use event_name::EventName;

use crate::ipc::CallbackFn;

/// Unique id of an event.
pub type EventId = u32;

/// Event Target
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(tag = "kind")]
#[non_exhaustive]
pub enum EventTarget {
  /// Any and all event targets.
  Any,

  /// Any [`Window`](crate::Window), [`Webview`](crate::Webview) or [`WebviewWindow`](crate::WebviewWindow) that have this label.
  AnyLabel {
    /// Target label.
    label: String,
  },

  /// [`App`](crate::App) and [`AppHandle`](crate::AppHandle) targets.
  App,

  /// [`Window`](crate::Window) target.
  Window {
    /// window label.
    label: String,
  },

  /// [`Webview`](crate::Webview) target.
  Webview {
    /// webview label.
    label: String,
  },

  /// [`WebviewWindow`](crate::WebviewWindow) target.
  WebviewWindow {
    /// webview window label.
    label: String,
  },
}

impl EventTarget {
  /// [`Self::Any`] target.
  pub fn any() -> Self {
    Self::Any
  }

  /// [`Self::App`] target.
  pub fn app() -> Self {
    Self::App
  }

  /// [`Self::AnyLabel`] target.
  pub fn labeled(label: impl Into<String>) -> Self {
    Self::AnyLabel {
      label: label.into(),
    }
  }

  /// [`Self::Window`] target.
  pub fn window(label: impl Into<String>) -> Self {
    Self::Window {
      label: label.into(),
    }
  }

  /// [`Self::Webview`] target.
  pub fn webview(label: impl Into<String>) -> Self {
    Self::Webview {
      label: label.into(),
    }
  }

  /// [`Self::WebviewWindow`] target.
  pub fn webview_window(label: impl Into<String>) -> Self {
    Self::WebviewWindow {
      label: label.into(),
    }
  }
}

impl<T: AsRef<str>> From<T> for EventTarget {
  fn from(value: T) -> Self {
    Self::AnyLabel {
      label: value.as_ref().to_string(),
    }
  }
}

impl FromStr for EventTarget {
  type Err = Infallible;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    Ok(Self::AnyLabel {
      label: s.to_string(),
    })
  }
}

/// Serialized emit arguments.
#[derive(Clone)]
pub struct EmitArgs {
  /// event name.
  event: EventName,
  /// Serialized payload.
  payload: String,
}

impl EmitArgs {
  pub fn new<S: Serialize>(event: EventName<&str>, payload: &S) -> crate::Result<Self> {
    #[cfg(feature = "tracing")]
    let _span = tracing::debug_span!("window::emit::serialize").entered();
    Ok(EmitArgs {
      event: event.into_owned(),
      payload: serde_json::to_string(payload)?,
    })
  }

  pub fn new_str(event: EventName<&str>, payload: String) -> crate::Result<Self> {
    #[cfg(feature = "tracing")]
    let _span = tracing::debug_span!("window::emit::json").entered();
    Ok(EmitArgs {
      event: event.into_owned(),
      payload,
    })
  }
}

/// An event that was emitted.
#[derive(Debug, Clone)]
pub struct Event {
  id: EventId,
  data: String,
}

impl Event {
  fn new(id: EventId, data: String) -> Self {
    Self { id, data }
  }

  /// The [`EventId`] of the handler that was triggered.
  pub fn id(&self) -> EventId {
    self.id
  }

  /// The event payload.
  pub fn payload(&self) -> &str {
    &self.data
  }
}

pub(crate) fn listen_js_script(
  listeners_object_name: &str,
  serialized_target: &str,
  event: EventName<&str>,
  event_id: EventId,
  handler: CallbackFn,
) -> String {
  let handler_id = handler.0;
  format!(
    "(function () {{
      if (window['{listeners_object_name}'] === void 0) {{
        Object.defineProperty(window, '{listeners_object_name}', {{ value: Object.create(null) }});
      }}
      if (window['{listeners_object_name}']['{event}'] === void 0) {{
        Object.defineProperty(window['{listeners_object_name}'], '{event}', {{ value: Object.create(null) }});
      }}
      const eventListeners = window['{listeners_object_name}']['{event}']
      const listener = {{
        target: {serialized_target},
        handlerId: {handler_id}
      }};
      Object.defineProperty(eventListeners, '{event_id}', {{ value: listener, configurable: true }});
    }})()
  ",
  )
}

/// Payloads past this size reach the page as a string for `JSON.parse`.
const JSON_PARSE_THRESHOLD: usize = 8 * 1024;

/// Writes a JSON payload as a JS expression. A large one goes in as a string for `JSON.parse`:
/// the engine scans a string literal and parses JSON natively, where an object literal of
/// the same size is compiled to bytecode first (a boot state of megabytes did exactly that).
fn write_payload(out: &mut String, payload: &str) {
  if payload.len() < JSON_PARSE_THRESHOLD {
    out.push_str(payload);
    return;
  }
  out.reserve(payload.len() + 16);
  out.push_str("JSON.parse('");
  // Inside a single-quoted literal: `\` and `'` are escaped, and a raw line break (whitespace
  // in pre-serialized JSON) becomes its escape, which JSON.parse reads as whitespace again.
  // U+2028 and U+2029 are valid in string literals since ES2019.
  let mut rest = payload;
  while let Some(i) = rest.find(['\\', '\'', '\n', '\r']) {
    out.push_str(&rest[..i]);
    out.push_str(match rest.as_bytes()[i] {
      b'\\' => "\\\\",
      b'\'' => "\\'",
      b'\n' => "\\n",
      _ => "\\r",
    });
    rest = &rest[i + 1..];
  }
  out.push_str(rest);
  out.push_str("')");
}

/// Appends the statement that hands one event to the page's listeners `ids`, in its own try
/// block so a listener that throws stops only this event.
pub(crate) fn write_emit_js(
  out: &mut String,
  event_emit_function_name: &str,
  emit_args: &EmitArgs,
  ids: &[u32],
) {
  use std::fmt::Write;
  let _ = write!(
    out,
    "try{{const f=window['{}'];f&&f({{event:'{}',payload:",
    event_emit_function_name,
    emit_args.event,
  );
  write_payload(out, &emit_args.payload);
  out.push_str("},[");
  for (i, id) in ids.iter().enumerate() {
    if i > 0 {
      out.push(',');
    }
    let _ = write!(out, "{id}");
  }
  out.push_str("])}catch(e){console.error(e)}\n");
}

pub(crate) fn unlisten_js_script(
  listeners_object_name: &str,
  event_arg: &str,
  event_id_arg: &str,
) -> String {
  format!(
    "(function () {{
        const listeners = (window['{listeners_object_name}'] || {{}})[{event_arg}]
        if (listeners) {{
          const listener = listeners[{event_id_arg}]
          if (listener) {{
            window.__TAURI_INTERNALS__.unregisterCallback(listener.handlerId)
          }}
        }}
      }})()
    ",
  )
}

pub(crate) fn event_initialization_script(function_name: &str, listeners: &str) -> String {
  format!(
    "Object.defineProperty(window, '{function_name}', {{
      value: function (eventData, ids) {{
        const listeners = (window['{listeners}'] && window['{listeners}'][eventData.event]) || []
        for (const id of ids) {{
          const listener = listeners[id]
          if (listener) {{
            eventData.id = id
            window.__TAURI_INTERNALS__.runCallback(listener.handlerId, eventData)
          }}
        }}
      }}
    }});
  "
  )
}

#[cfg(test)]
mod tests {
  use super::*;
  #[test]
  fn test_illegal_event_name() {
    let s = EventName::new("some\r illegal event name")
      .unwrap_err()
      .to_string();
    assert_eq!(
      "only alphanumeric, '-', '/', ':', '_' permitted for event names: \"some\\r illegal event name\"",
      s
    );
  }
}

#[cfg(test)]
mod payload_tests {
  use super::write_payload;

  #[test]
  fn a_large_payload_round_trips_through_json_parse_escaping() {
    let value = serde_json::json!({ "text": "it's a \\ path\nwith \u{2028} and \"quotes\"", "pad": "x".repeat(9000) });
    let json = serde_json::to_string_pretty(&value).unwrap();
    let mut out = String::new();
    write_payload(&mut out, &json);
    assert!(out.starts_with("JSON.parse('") && out.ends_with("')"));
    // Undo the JS string escapes the way the engine reads the literal.
    let inner = &out["JSON.parse('".len()..out.len() - 2];
    let mut unescaped = String::new();
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
      if c == '\\' {
        match chars.next().unwrap() {
          'n' => unescaped.push('\n'),
          'r' => unescaped.push('\r'),
          other => unescaped.push(other),
        }
      } else {
        assert_ne!(c, '\'', "an unescaped quote would end the literal");
        assert_ne!(c, '\n', "a raw line break would end the literal");
        unescaped.push(c);
      }
    }
    assert_eq!(serde_json::from_str::<serde_json::Value>(&unescaped).unwrap(), value);
  }

  #[test]
  fn a_small_payload_stays_a_literal() {
    let mut out = String::new();
    write_payload(&mut out, "{\"a\":1}");
    assert_eq!(out, "{\"a\":1}");
  }
}
