//! WS-Management SOAP protocol layer.
//!
//! - `namespaces` -- URI constants for WS-Man actions and resources
//! - `envelope` -- SOAP envelope builders for shell lifecycle operations
//! - `parser` -- response parsers for shell IDs, command IDs, and output streams

pub(crate) mod envelope;
pub(crate) mod namespaces;
pub(crate) mod parser;

// Re-export for internal use
pub(crate) use envelope::*;
pub(crate) use parser::parse_enumerate_response;
// `mod soap` is private at the lib root, so these re-exports are not
// externally visible despite being `pub`. They are marked `pub` (rather
// than `pub(crate)`) so lib.rs can re-export them under the `__internal`
// feature for fuzz targets via `pub use soap::{...}`.
#[allow(unreachable_pub)]
pub use parser::{check_soap_fault, parse_command_id, parse_receive_output, parse_shell_id};
// Re-export ReceiveOutput as fully public so lib.rs can `pub use` it.
pub use parser::ReceiveOutput;
