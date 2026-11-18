use crate::{AccountCache, CertCache};
use async_trait::async_trait;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyUsagePurpose,
    PKCS_ECDSA_P256_SHA256, date_time_ymd,
};
use std::fmt::Debug;
use std::marker::PhantomData;
use std::sync::Arc;
use std::sync::atomic::AtomicPtr;

/// Test cache, which generates certificates for ACME incompatible test environments.
/// ```rust
/// # use tokio_rustls_acme::{AcmeConfig};
/// # use tokio_rustls_acme::caches::{DirCache, TestCache};
/// # let test_environment = true;
/// let mut config = AcmeConfig::new(["example.com"])
///     .cache(DirCache::new("./cache"));
/// if test_environment {
///     config = config.cache(TestCache::new());
/// }
/// ```
#[derive(Clone)]
pub struct TestCache<EC: Debug = std::io::Error, EA: Debug = std::io::Error> {
    ca_issuer: Arc<rcgen::Issuer<'static, rcgen::KeyPair>>,
    ca_pem: Arc<String>,
    _cert_error: PhantomData<AtomicPtr<Box<EC>>>,
    _account_error: PhantomData<AtomicPtr<Box<EA>>>,
}

impl<EC: Debug, EA: Debug> Default for TestCache<EC, EA> {
    fn default() -> Self {
        let mut params = CertificateParams::default();
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CountryName, "US");
        distinguished_name.push(DnType::OrganizationName, "Test CA");
        distinguished_name.push(DnType::CommonName, "Test CA");
        params.distinguished_name = distinguished_name;

        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.not_before = date_time_ymd(2000, 1, 1);
        params.not_after = date_time_ymd(3000, 1, 1);

        let key_pair = rcgen::KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let ca_cert = params.self_signed(&key_pair).unwrap();
        let ca_pem = ca_cert.pem();
        let ca_issuer = rcgen::Issuer::new(params, key_pair);

        Self {
            ca_issuer: ca_issuer.into(),
            ca_pem: ca_pem.into(),
            _cert_error: Default::default(),
            _account_error: Default::default(),
        }
    }
}

impl<EC: Debug, EA: Debug> TestCache<EC, EA> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn ca_pem(&self) -> &str {
        &self.ca_pem
    }
}

#[async_trait]
impl<EC: Debug, EA: Debug> CertCache for TestCache<EC, EA> {
    type EC = EC;
    async fn load_cert(
        &self,
        domains: &[String],
        _directory_url: &str,
    ) -> Result<Option<Vec<u8>>, Self::EC> {
        let key_pair = rcgen::KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::new(domains).unwrap();
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, "Test Cert");
        params.distinguished_name = distinguished_name;
        params.not_before = date_time_ymd(2000, 1, 1);
        params.not_after = date_time_ymd(3000, 1, 1);

        let cert = match params.signed_by(&key_pair, &self.ca_issuer) {
            Ok(cert) => cert,
            Err(err) => {
                log::error!("test cache: generation error: {err:?}");
                return Ok(None);
            }
        };

        let cert_pem = cert.pem();

        let pem = [
            &key_pair.serialize_pem(),
            "\n",
            &cert_pem,
            "\n",
            &self.ca_pem,
        ]
        .concat();
        Ok(Some(pem.into_bytes()))
    }
    async fn store_cert(
        &self,
        _domains: &[String],
        _directory_url: &str,
        _cert: &[u8],
    ) -> Result<(), Self::EC> {
        log::info!("test cache configured, could not store certificate");
        Ok(())
    }
}

#[async_trait]
impl<EC: Debug, EA: Debug> AccountCache for TestCache<EC, EA> {
    type EA = EA;
    async fn load_account(
        &self,
        _contact: &[String],
        _directory_url: &str,
    ) -> Result<Option<Vec<u8>>, Self::EA> {
        log::info!("test cache configured, could not load account");
        Ok(None)
    }
    async fn store_account(
        &self,
        _contact: &[String],
        _directory_url: &str,
        _account: &[u8],
    ) -> Result<(), Self::EA> {
        log::info!("test cache configured, could not store account");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::caches::DirCache;
    use crate::{AccountCache, CertCache};
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_dir_cache_cert_and_account_roundtrip() {
        let tmp_dir = tempdir().unwrap();
        // Use a non-existent subdirectory to verify create_dir_all works
        let cache_path = tmp_dir.path().join("nested/acme_cache");
        let cache = DirCache::new(&cache_path);

        let domains = vec!["example.com".to_string(), "www.example.com".to_string()];
        let contacts = vec!["mailto:admin@example.com".to_string()];
        let dir_url = "https://acme-staging-v02.api.letsencrypt.org/directory";

        // 1. Missing entries return Ok(None)
        assert_eq!(cache.load_cert(&domains, dir_url).await.unwrap(), None);
        assert_eq!(cache.load_account(&contacts, dir_url).await.unwrap(), None);

        // 2. Store and load certificate
        let cert_data = b"-----BEGIN PRIVATE KEY-----\n...\n-----BEGIN CERTIFICATE-----\n...";
        cache
            .store_cert(&domains, dir_url, cert_data)
            .await
            .unwrap();
        assert_eq!(
            cache.load_cert(&domains, dir_url).await.unwrap().as_deref(),
            Some(&cert_data[..])
        );

        // 3. Atomic overwrite of existing certificate
        let updated_cert = b"updated-cert-pem-data";
        cache
            .store_cert(&domains, dir_url, updated_cert)
            .await
            .unwrap();
        assert_eq!(
            cache.load_cert(&domains, dir_url).await.unwrap().as_deref(),
            Some(&updated_cert[..])
        );

        // 4. Store and load account
        let account_data = b"account-credentials-json";
        cache
            .store_account(&contacts, dir_url, account_data)
            .await
            .unwrap();
        assert_eq!(
            cache
                .load_account(&contacts, dir_url)
                .await
                .unwrap()
                .as_deref(),
            Some(&account_data[..])
        );

        // 5. Verify no leftover .tmp. files and 0600 permissions on Unix
        let mut entries = std::fs::read_dir(&cache_path)
            .unwrap()
            .map(|res| res.unwrap().path())
            .collect::<Vec<_>>();
        entries.sort();
        assert_eq!(entries.len(), 2);

        for entry in entries {
            let name = entry.file_name().unwrap().to_string_lossy();
            assert!(
                !name.starts_with('.'),
                "unexpected leftover temporary file: {name}"
            );
            assert!(
                name.starts_with("cached_cert_") || name.starts_with("cached_account_"),
                "unexpected file in cache dir: {name}"
            );

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(&entry).unwrap().permissions().mode() & 0o777;
                assert_eq!(mode, 0o600, "expected 0600 permissions on {entry:?}");
            }
        }
    }
}
