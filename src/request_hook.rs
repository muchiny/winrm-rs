//! Optional admission callback for each NTLM HTTP exchange.
use crate::WinrmError;
use std::sync::Arc;

/// Called immediately before every HTTP send, including NTLM negotiate,
/// authenticate, sealed requests and retries. Returning an error refuses the
/// send. The callback receives no credential or request data.
///
/// Currently supported for NTLM only; attaching it with another authentication
/// method returns an error before any network contact. No callback means the
/// existing behavior. reqwest transparent retries are disabled for this path.
#[derive(Clone)]
pub struct RequestHook(Arc<dyn Fn() -> Result<(), WinrmError> + Send + Sync>);
impl RequestHook {
    pub fn new(hook: impl Fn() -> Result<(), WinrmError> + Send + Sync + 'static) -> Self {
        Self(Arc::new(hook))
    }
    pub(crate) fn call(&self) -> Result<(), WinrmError> {
        (self.0)()
    }
}
