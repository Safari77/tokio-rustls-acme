use crate::acme::ACME_TLS_ALPN_NAME;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex;

/// Cert resolver that serves the issued certificate to application traffic
/// and per-domain validation certificates to `tls-alpn-01` clients.
#[derive(Debug)]
pub struct ResolvesServerCertAcme {
    inner: Mutex<Inner>,
}

#[derive(Debug)]
struct Inner {
    cert: Option<Arc<CertifiedKey>>,
    auth_keys: BTreeMap<String, Arc<CertifiedKey>>,
}

impl ResolvesServerCertAcme {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Inner {
                cert: None,
                auth_keys: Default::default(),
            }),
        })
    }
    pub(crate) fn set_cert(&self, cert: Arc<CertifiedKey>) {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).cert = Some(cert);
    }
    pub(crate) fn set_auth_key(&self, domain: String, cert: Arc<CertifiedKey>) {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .auth_keys
            .insert(domain.to_ascii_lowercase(), cert);
    }
    pub(crate) fn remove_auth_key(&self, domain: &str) {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .auth_keys
            .remove(&domain.to_ascii_lowercase());
    }
}

impl ResolvesServerCert for ResolvesServerCertAcme {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        let is_acme_challenge = client_hello
            .alpn()
            .into_iter()
            .flatten()
            .eq([ACME_TLS_ALPN_NAME]);
        if is_acme_challenge {
            match client_hello.server_name() {
                None => {
                    log::debug!("client did not supply SNI");
                    None
                }
                Some(domain) => {
                    let domain = domain.to_ascii_lowercase();
                    self.inner
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .auth_keys
                        .get(&domain)
                        .cloned()
                }
            }
        } else {
            self.inner
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .cert
                .clone()
        }
    }
}
