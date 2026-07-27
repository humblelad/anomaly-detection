//! Envoy WASM HTTP filter — the trust boundary of the detection pipeline.
//!
//! On every request it:
//!   1. strips any client-supplied `X-Detection-JA4` (the trusted header may
//!      only ever be minted here — anti-spoofing),
//!   2. reads `X-JA4-Raw` set by the ja4-sidecar (which has already stripped
//!      client-supplied copies — two independent enforcement points),
//!   3. HMAC-SHA256-signs `ja4|timestamp` with a shared key,
//!   4. injects `X-Detection-JA4: v1;ja4=...;ts=...;sig=...` and drops the
//!      unsigned raw header.
//!
//! Everything downstream verifies the signature instead of trusting the
//! network path. The key is static for the demo; production would rotate it
//! and carry a `kid` so verifiers span rotation windows.

use hmac::{Hmac, Mac};
use sha2::Sha256;

pub const TRUSTED_HEADER: &str = "x-detection-ja4";
pub const RAW_HEADER: &str = "x-ja4-raw";

/// HMAC-SHA256 over the `ja4|ts` payload. Kept free of proxy-wasm types so
/// it is unit-testable on the host target.
pub fn sign(key: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(payload);
    mac.finalize().into_bytes().to_vec()
}

/// Builds the trusted header value for a fingerprint at a given time.
pub fn trusted_header_value(key: &[u8], ja4: &str, ts: u64) -> String {
    let payload = format!("{ja4}|{ts}");
    let sig = hex::encode(sign(key, payload.as_bytes()));
    format!("v1;ja4={ja4};ts={ts};sig={sig}")
}

#[cfg(target_arch = "wasm32")]
mod filter {
    use super::{trusted_header_value, RAW_HEADER, TRUSTED_HEADER};
    use log::{error, info};
    use proxy_wasm::traits::{Context, HttpContext, RootContext};
    use proxy_wasm::types::{Action, ContextType, LogLevel};
    use std::time::UNIX_EPOCH;

    #[derive(serde::Deserialize, Clone, Default)]
    struct FilterConfig {
        hmac_key: String,
    }

    proxy_wasm::main! {{
        proxy_wasm::set_log_level(LogLevel::Info);
        proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> {
            Box::new(DetectionRoot::default())
        });
    }}

    #[derive(Default)]
    struct DetectionRoot {
        config: FilterConfig,
    }

    impl Context for DetectionRoot {}

    impl RootContext for DetectionRoot {
        fn on_configure(&mut self, _plugin_configuration_size: usize) -> bool {
            let Some(bytes) = self.get_plugin_configuration() else {
                error!("detection filter: missing plugin configuration");
                return false;
            };
            match serde_json::from_slice::<FilterConfig>(&bytes) {
                Ok(cfg) if !cfg.hmac_key.is_empty() => {
                    info!(
                        "detection filter configured (key length {})",
                        cfg.hmac_key.len()
                    );
                    self.config = cfg;
                    true
                }
                Ok(_) => {
                    error!("detection filter: hmac_key must not be empty");
                    false
                }
                Err(e) => {
                    error!("detection filter: bad configuration: {e}");
                    false
                }
            }
        }

        fn create_http_context(&self, _context_id: u32) -> Option<Box<dyn HttpContext>> {
            Some(Box::new(DetectionFilter {
                config: self.config.clone(),
            }))
        }

        fn get_type(&self) -> Option<ContextType> {
            Some(ContextType::HttpContext)
        }
    }

    struct DetectionFilter {
        config: FilterConfig,
    }

    impl Context for DetectionFilter {}

    impl HttpContext for DetectionFilter {
        fn on_http_request_headers(
            &mut self,
            _num_headers: usize,
            _end_of_stream: bool,
        ) -> Action {
            // Anti-spoofing: unconditionally remove the trusted header
            // before doing anything else. A client that sends it gains
            // nothing.
            self.set_http_request_header(TRUSTED_HEADER, None);

            let ja4 = self.get_http_request_header(RAW_HEADER).unwrap_or_default();

            let ts = self
                .get_current_time()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);

            // An empty ja4 (sidecar peek failed) is still signed: downstream
            // can distinguish "verified absent" from "tampered/missing".
            let value = trusted_header_value(self.config.hmac_key.as_bytes(), &ja4, ts);
            self.set_http_request_header(TRUSTED_HEADER, Some(&value));

            // Nothing downstream should ever read the unsigned raw header.
            self.set_http_request_header(RAW_HEADER, None);

            Action::Continue
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{sign, trusted_header_value};

    #[test]
    fn sign_is_deterministic_and_key_dependent() {
        let a = sign(b"key-1", b"t13d1516h2_abc_def|1700000000");
        let b = sign(b"key-1", b"t13d1516h2_abc_def|1700000000");
        let c = sign(b"key-2", b"t13d1516h2_abc_def|1700000000");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn known_vector_matches_python_verifier() {
        // Mirrors demo-backend verification: hmac.new(key, payload, sha256).
        // Expected value computed independently with Python:
        //   hmac.new(b"demo-key", b"ja4|123", hashlib.sha256).hexdigest()
        let sig = hex::encode(sign(b"demo-key", b"ja4|123"));
        assert_eq!(
            sig,
            "3e9c3e8f98f543e6f42a74cdcbbd0cc21369dca0907dc9a22b451482f9b7cc80"
        );
    }

    #[test]
    fn header_value_shape() {
        let v = trusted_header_value(b"k", "t13d1516h2_x_y", 1700000000);
        assert!(v.starts_with("v1;ja4=t13d1516h2_x_y;ts=1700000000;sig="));
    }
}
