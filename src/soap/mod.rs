//! WS-Management SOAP protocol layer.
//!
//! - `namespaces` -- URI constants for WS-Man actions and resources
//! - `envelope` -- SOAP envelope builders for shell lifecycle operations
//! - `parser` -- response parsers for shell IDs, command IDs, and output streams
//! - `clixml` -- incremental decoder for PowerShell CLIXML on stderr
//! - `xml` -- how a server's XML is read (`quick-xml`): what a document may
//!   hold, and the walk the response parsers are written on
//! - `scan` -- forward-only substring search of the CLIXML decoder

pub(crate) mod clixml;
pub(crate) mod envelope;
pub(crate) mod namespaces;
pub(crate) mod parser;
mod scan;
mod xml;

// Re-export for internal use
pub(crate) use envelope::*;
pub(crate) use parser::{
    check_answer, is_timed_out_fault, parse_command_id, parse_enumerate_response,
    parse_receive_output, parse_receive_output_raw, parse_shell_id,
};
// Re-export ReceiveOutput as fully public so lib.rs can `pub use` it.
pub use parser::ReceiveOutput;
// The public stateful stderr decoder, re-exported from the crate root.
pub use clixml::StderrDecoder;
