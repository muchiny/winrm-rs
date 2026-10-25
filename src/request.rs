//! What a `before_send_with` hook sees of a request.

use crate::soap::namespaces::{
    ACTION_COMMAND, ACTION_CREATE, ACTION_DELETE, ACTION_DISCONNECT, ACTION_ENUMERATE, ACTION_PULL,
    ACTION_RECEIVE, ACTION_RECONNECT, ACTION_SEND, ACTION_SIGNAL,
};

/// The WS-Management operation of a request, from its `wsa:Action`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RequestKind {
    /// Shell Create: [`create_shell`](crate::WinrmClient::create_shell),
    /// [`open_shell`](crate::WinrmClient::open_shell),
    /// [`open_psrp_shell`](crate::WinrmClient::open_psrp_shell), and every
    /// high-level call that opens a shell.
    Create,
    /// Shell Delete: [`delete_shell`](crate::WinrmClient::delete_shell),
    /// [`Shell::close`](crate::Shell::close), the clean-up of the high-level
    /// calls, and the fallback of [`Shell::disconnect`](crate::Shell::disconnect).
    Delete,
    /// Start a command or a PSRP pipeline.
    Command,
    /// Poll output.
    Receive,
    /// The WS-Management `Send` action (stdin, PSRP fragments).
    SendInput,
    /// Terminate, Ctrl+C, the PSRP stop.
    Signal,
    /// Disconnect a shell.
    Disconnect,
    /// Reconnect a shell.
    Reconnect,
    /// Start a WQL enumeration ([`run_wql`](crate::WinrmClient::run_wql)).
    Enumerate,
    /// Fetch the next WQL results ([`run_wql`](crate::WinrmClient::run_wql)).
    Pull,
    /// An action this version does not know; no request this crate builds
    /// has it.
    Other,
}

impl RequestKind {
    /// The kind of the `wsa:Action` URI `action`, by exact match.
    pub(crate) fn from_action(action: &str) -> RequestKind {
        match action {
            ACTION_CREATE => RequestKind::Create,
            ACTION_DELETE => RequestKind::Delete,
            ACTION_COMMAND => RequestKind::Command,
            ACTION_RECEIVE => RequestKind::Receive,
            ACTION_SEND => RequestKind::SendInput,
            ACTION_SIGNAL => RequestKind::Signal,
            ACTION_DISCONNECT => RequestKind::Disconnect,
            ACTION_RECONNECT => RequestKind::Reconnect,
            ACTION_ENUMERATE => RequestKind::Enumerate,
            ACTION_PULL => RequestKind::Pull,
            _ => RequestKind::Other,
        }
    }
}

/// What a [`before_send_with`](crate::WinrmClientBuilder::before_send_with)
/// hook sees of the request it may refuse, borrowed for the call.
#[derive(Debug, Clone)]
pub struct OutgoingRequest<'a> {
    host: &'a str,
    action: &'a str,
    kind: RequestKind,
    attempt: u32,
}

impl<'a> OutgoingRequest<'a> {
    pub(crate) fn new(host: &'a str, action: &'a str, kind: RequestKind, attempt: u32) -> Self {
        Self {
            host,
            action,
            kind,
            attempt,
        }
    }

    /// The host this request goes to, as the call gave it. A host string
    /// with a scheme, userinfo, port or path is refused before the hook
    /// runs, so this is exactly the host the endpoint URL uses (an IPv6
    /// literal keeps its brackets). It is not resolved, lower-cased or
    /// converted to punycode (the URL parser converts a Unicode name), and
    /// with a proxy it is the WinRM host, not the TCP peer. Compare it
    /// case-insensitively and strip a trailing dot before using it as a key.
    pub fn host(&self) -> &'a str {
        self.host
    }

    /// The `wsa:Action` URI as sent; empty for a body without one (no
    /// request this crate builds).
    pub fn action(&self) -> &'a str {
        self.action
    }

    /// The [`RequestKind`] of [`Self::action`].
    pub fn kind(&self) -> RequestKind {
        self.kind
    }

    /// 0 for the first try, `n` for the n-th retry
    /// ([`WinrmConfig::max_retries`](crate::WinrmConfig::max_retries)); each
    /// attempt is a separate approval.
    pub fn attempt(&self) -> u32 {
        self.attempt
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_action_constant_has_its_kind() {
        use crate::soap::namespaces::*;
        for (action, kind) in [
            (ACTION_CREATE, RequestKind::Create),
            (ACTION_DELETE, RequestKind::Delete),
            (ACTION_COMMAND, RequestKind::Command),
            (ACTION_RECEIVE, RequestKind::Receive),
            (ACTION_SEND, RequestKind::SendInput),
            (ACTION_SIGNAL, RequestKind::Signal),
            (ACTION_DISCONNECT, RequestKind::Disconnect),
            (ACTION_RECONNECT, RequestKind::Reconnect),
            (ACTION_ENUMERATE, RequestKind::Enumerate),
            (ACTION_PULL, RequestKind::Pull),
        ] {
            assert_eq!(RequestKind::from_action(action), kind, "{action}");
        }
        assert_eq!(RequestKind::from_action(""), RequestKind::Other);
        assert_eq!(
            RequestKind::from_action("http://schemas.xmlsoap.org/ws/2004/09/transfer/Get"),
            RequestKind::Other
        );
        // Exact match only.
        assert_eq!(
            RequestKind::from_action(&ACTION_DELETE.to_uppercase()),
            RequestKind::Other
        );
        assert_eq!(
            RequestKind::from_action(&format!("{ACTION_DELETE}x")),
            RequestKind::Other
        );
    }
}
