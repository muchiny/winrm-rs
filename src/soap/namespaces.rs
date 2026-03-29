//! WS-Management namespace URIs and protocol constants.

/// WinRS command shell resource URI.
pub(crate) const RESOURCE_URI_CMD: &str =
    "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd";

/// SOAP action for shell creation.
pub(crate) const ACTION_CREATE: &str =
    "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create";

/// SOAP action for shell deletion.
pub(crate) const ACTION_DELETE: &str =
    "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete";

/// SOAP action for command execution.
pub(crate) const ACTION_COMMAND: &str =
    "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command";

/// SOAP action for output polling.
pub(crate) const ACTION_RECEIVE: &str =
    "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive";

/// SOAP action for signal delivery.
pub(crate) const ACTION_SIGNAL: &str =
    "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Signal";

/// SOAP action for input delivery.
pub(crate) const ACTION_SEND: &str =
    "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Send";

/// Signal code: terminate command.
pub(crate) const SIGNAL_TERMINATE: &str =
    "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/terminate";

/// Signal code: Ctrl+C.
pub(crate) const SIGNAL_CTRL_C: &str =
    "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/ctrl_c";

/// Command state indicating completion.
pub(crate) const COMMAND_STATE_DONE: &str =
    "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done";

/// Anonymous reply-to address.
pub(crate) const REPLY_TO_ANONYMOUS: &str =
    "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous";
