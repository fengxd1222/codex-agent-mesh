//! Current-user DPAPI envelope for the endpoint authentication key.

#![allow(clippy::missing_errors_doc)]

use crate::{AUTH_TAG_LENGTH, EndpointKey, NativeError, NativeErrorCode, NativeOperation};

/// A conservative bound for the small DPAPI envelope accepted at this boundary.
pub const MAX_PROTECTED_ENDPOINT_KEY_BYTES: usize = 64 * 1024;
const ENDPOINT_KEY_DOMAIN: &[u8] = b"codex-agent-mesh\0endpoint-key-dpapi-v1\0";
/// Separate DPAPI entropy domain for the dashboard secret so an endpoint
/// key envelope can never be replayed as a dashboard secret and back.
const DASHBOARD_ENTROPY_DOMAIN: &[u8] = b"codex-agent-mesh\0dashboard-secret-dpapi-v1\0";

/// Opaque, non-secret DPAPI ciphertext suitable for durable storage.
#[derive(Clone, Eq, PartialEq)]
pub struct ProtectedEndpointKey(Vec<u8>);

impl ProtectedEndpointKey {
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, NativeError> {
        if bytes.is_empty() || bytes.len() > MAX_PROTECTED_ENDPOINT_KEY_BYTES {
            return Err(invalid(NativeOperation::UnprotectEndpointKey));
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for ProtectedEndpointKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProtectedEndpointKey")
            .field("length", &self.0.len())
            .finish_non_exhaustive()
    }
}

pub fn protect_endpoint_key(
    key: &EndpointKey,
    install_id: &str,
) -> Result<ProtectedEndpointKey, NativeError> {
    validate_install_id(install_id, NativeOperation::ProtectEndpointKey)?;
    platform::protect(key, install_id, ENDPOINT_KEY_DOMAIN)
}

pub fn unprotect_endpoint_key(
    protected: &ProtectedEndpointKey,
    install_id: &str,
) -> Result<EndpointKey, NativeError> {
    validate_install_id(install_id, NativeOperation::UnprotectEndpointKey)?;
    platform::unprotect(protected, install_id, ENDPOINT_KEY_DOMAIN)
}

/// Protects the dashboard session secret for the same install. Uses a
/// distinct entropy domain from the endpoint key so envelopes are not
/// interchangeable across the two boundaries.
pub fn protect_dashboard_secret(
    key: &EndpointKey,
    install_id: &str,
) -> Result<ProtectedEndpointKey, NativeError> {
    validate_install_id(install_id, NativeOperation::ProtectEndpointKey)?;
    platform::protect(key, install_id, DASHBOARD_ENTROPY_DOMAIN)
}

/// Unprotects a dashboard session secret previously written by
/// [`protect_dashboard_secret`] for the same install.
pub fn unprotect_dashboard_secret(
    protected: &ProtectedEndpointKey,
    install_id: &str,
) -> Result<EndpointKey, NativeError> {
    validate_install_id(install_id, NativeOperation::UnprotectEndpointKey)?;
    platform::unprotect(protected, install_id, DASHBOARD_ENTROPY_DOMAIN)
}

fn entropy_with_domain(domain: &[u8], install_id: &str) -> Vec<u8> {
    let mut value = Vec::with_capacity(domain.len() + install_id.len());
    value.extend_from_slice(domain);
    value.extend_from_slice(install_id.as_bytes());
    value
}

fn validate_install_id(install_id: &str, operation: NativeOperation) -> Result<(), NativeError> {
    if install_id.len() == 32
        && install_id
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err(invalid(operation))
    }
}

const fn invalid(operation: NativeOperation) -> NativeError {
    NativeError::new(NativeErrorCode::SecretInvalid, operation)
}

#[cfg(windows)]
mod platform {
    use std::{ptr, slice};

    use windows_sys::Win32::Foundation::{GetLastError, HLOCAL, LocalFree};
    use windows_sys::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
    };
    use zeroize::Zeroize;

    use super::{
        AUTH_TAG_LENGTH, EndpointKey, MAX_PROTECTED_ENDPOINT_KEY_BYTES, NativeError,
        NativeErrorCode, NativeOperation, ProtectedEndpointKey, entropy_with_domain, invalid,
    };

    struct LocalBlob {
        pointer: HLOCAL,
        length: usize,
        secret: bool,
    }

    impl LocalBlob {
        fn from_output(blob: CRYPT_INTEGER_BLOB, secret: bool) -> Self {
            Self {
                pointer: blob.pbData.cast(),
                length: blob.cbData as usize,
                secret,
            }
        }

        fn is_empty_or_null(&self) -> bool {
            self.length == 0 || self.pointer.is_null()
        }

        fn bytes(&self) -> &[u8] {
            debug_assert!(!self.is_empty_or_null());
            // SAFETY: DPAPI returned `pointer` with exactly `length` initialized
            // bytes and this owner keeps it allocated for the returned borrow.
            unsafe { slice::from_raw_parts(self.pointer.cast(), self.length) }
        }
    }

    impl Drop for LocalBlob {
        fn drop(&mut self) {
            if self.secret && !self.pointer.is_null() && self.length != 0 {
                // SAFETY: this is the unique mutable owner of the DPAPI output
                // allocation and `length` is the byte count returned by DPAPI.
                unsafe { slice::from_raw_parts_mut(self.pointer.cast::<u8>(), self.length) }
                    .zeroize();
            }
            // SAFETY: DPAPI allocates output with LocalAlloc; this wrapper owns
            // it exactly once and LocalFree is the documented matching release.
            unsafe { LocalFree(self.pointer) };
        }
    }

    pub(super) fn protect(
        key: &EndpointKey,
        install_id: &str,
        domain: &[u8],
    ) -> Result<ProtectedEndpointKey, NativeError> {
        let entropy = entropy_with_domain(domain, install_id);
        let input = blob(key.secret_bytes());
        let optional_entropy = blob(&entropy);
        let mut output = CRYPT_INTEGER_BLOB::default();
        // SAFETY: both input blobs borrow live slices whose lengths fit u32;
        // output is writable and DPAPI is forbidden from displaying UI.
        let succeeded = unsafe {
            CryptProtectData(
                &raw const input,
                ptr::null(),
                &raw const optional_entropy,
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &raw mut output,
            )
        };
        if succeeded == 0 {
            // Capture the DPAPI error before LocalFree in the output guard.
            let error = os_failure(NativeOperation::ProtectEndpointKey);
            drop(LocalBlob::from_output(output, false));
            return Err(error);
        }
        let output = LocalBlob::from_output(output, false);
        if output.is_empty_or_null() || output.length > MAX_PROTECTED_ENDPOINT_KEY_BYTES {
            return Err(invalid(NativeOperation::ProtectEndpointKey));
        }
        ProtectedEndpointKey::from_bytes(output.bytes().to_vec())
    }

    pub(super) fn unprotect(
        protected: &ProtectedEndpointKey,
        install_id: &str,
        domain: &[u8],
    ) -> Result<EndpointKey, NativeError> {
        let entropy = entropy_with_domain(domain, install_id);
        let input = blob(protected.as_bytes());
        let optional_entropy = blob(&entropy);
        let mut output = CRYPT_INTEGER_BLOB::default();
        // SAFETY: both input blobs borrow live, bounded slices; output is
        // writable and DPAPI is forbidden from displaying UI.
        let succeeded = unsafe {
            CryptUnprotectData(
                &raw const input,
                ptr::null_mut(),
                &raw const optional_entropy,
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &raw mut output,
            )
        };
        if succeeded == 0 {
            // A defensive guard zeroes/frees even a partial failure output.
            let error = os_failure(NativeOperation::UnprotectEndpointKey);
            drop(LocalBlob::from_output(output, true));
            return Err(error);
        }
        let output = LocalBlob::from_output(output, true);
        if output.is_empty_or_null() || output.length != AUTH_TAG_LENGTH {
            return Err(invalid(NativeOperation::UnprotectEndpointKey));
        }
        let mut bytes = [0_u8; AUTH_TAG_LENGTH];
        bytes.copy_from_slice(output.bytes());
        Ok(EndpointKey::from_bytes(bytes))
    }

    fn blob(bytes: &[u8]) -> CRYPT_INTEGER_BLOB {
        CRYPT_INTEGER_BLOB {
            cbData: u32::try_from(bytes.len()).expect("bounded DPAPI input fits u32"),
            pbData: bytes.as_ptr().cast_mut(),
        }
    }

    fn os_failure(operation: NativeOperation) -> NativeError {
        // SAFETY: called immediately after a failing Win32 call.
        let code = unsafe { GetLastError() };
        NativeError::with_os_code(NativeErrorCode::SecretProtectionFailed, operation, code)
    }

    #[cfg(test)]
    pub(super) fn protect_arbitrary_for_test(
        plaintext: &[u8],
        install_id: &str,
    ) -> ProtectedEndpointKey {
        // The endpoint-key entropy domain keeps the arbitrary-plaintext
        // test envelopes in the same family as production protects.
        let entropy = entropy_with_domain(super::ENDPOINT_KEY_DOMAIN, install_id);
        let input = blob(plaintext);
        let optional_entropy = blob(&entropy);
        let mut output = CRYPT_INTEGER_BLOB::default();
        // SAFETY: test slices and output satisfy the same DPAPI invariants as
        // the production protect path; UI is forbidden.
        assert_ne!(
            unsafe {
                CryptProtectData(
                    &raw const input,
                    ptr::null(),
                    &raw const optional_entropy,
                    ptr::null(),
                    ptr::null(),
                    CRYPTPROTECT_UI_FORBIDDEN,
                    &raw mut output,
                )
            },
            0,
            "protect arbitrary test plaintext"
        );
        let output = LocalBlob::from_output(output, false);
        ProtectedEndpointKey::from_bytes(output.bytes().to_vec()).expect("bounded test envelope")
    }
}

#[cfg(not(windows))]
mod platform {
    use super::*;

    pub(super) fn protect(
        _key: &EndpointKey,
        _install_id: &str,
        _domain: &[u8],
    ) -> Result<ProtectedEndpointKey, NativeError> {
        Err(NativeError::new(
            NativeErrorCode::UnsupportedPlatform,
            NativeOperation::ProtectEndpointKey,
        ))
    }

    pub(super) fn unprotect(
        _protected: &ProtectedEndpointKey,
        _install_id: &str,
        _domain: &[u8],
    ) -> Result<EndpointKey, NativeError> {
        Err(NativeError::new(
            NativeErrorCode::UnsupportedPlatform,
            NativeOperation::UnprotectEndpointKey,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INSTALL_ID: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn debug_output_is_redacted() {
        let key = EndpointKey::from_bytes([0x5a; AUTH_TAG_LENGTH]);
        assert_eq!(format!("{key:?}"), "EndpointKey([REDACTED])");
        let protected = ProtectedEndpointKey::from_bytes(vec![0x5a; 32]).expect("valid envelope");
        let debug = format!("{protected:?}");
        assert!(!debug.contains("5a"));
    }

    #[test]
    fn rejects_noncanonical_install_id_and_envelope_bounds() {
        let key = EndpointKey::from_bytes([1; AUTH_TAG_LENGTH]);
        assert_eq!(
            protect_endpoint_key(&key, "ABCDEF0123456789ABCDEF0123456789")
                .expect_err("uppercase is not canonical")
                .code(),
            NativeErrorCode::SecretInvalid
        );
        assert!(ProtectedEndpointKey::from_bytes(Vec::new()).is_err());
        assert!(
            ProtectedEndpointKey::from_bytes(vec![0; MAX_PROTECTED_ENDPOINT_KEY_BYTES + 1])
                .is_err()
        );
    }

    #[cfg(windows)]
    #[test]
    fn dashboard_secret_domain_is_separate_from_endpoint_key() {
        let key = EndpointKey::from_bytes([0x51; AUTH_TAG_LENGTH]);
        let dashboard = protect_dashboard_secret(&key, INSTALL_ID).expect("protect dashboard");
        let recovered =
            unprotect_dashboard_secret(&dashboard, INSTALL_ID).expect("unprotect dashboard");
        assert!(recovered.secret_bytes() == key.secret_bytes());
        // An endpoint-key envelope must not open as a dashboard secret and
        // a dashboard envelope must not open as an endpoint key.
        let endpoint = protect_endpoint_key(&key, INSTALL_ID).expect("protect endpoint");
        assert!(unprotect_dashboard_secret(&endpoint, INSTALL_ID).is_err());
        assert!(unprotect_endpoint_key(&dashboard, INSTALL_ID).is_err());
        assert!(
            unprotect_dashboard_secret(&dashboard, "1123456789abcdef0123456789abcdef").is_err()
        );
    }

    #[cfg(windows)]
    #[test]
    fn dpapi_round_trip_is_bound_to_install_id_and_tamper_evident() {
        let key = EndpointKey::from_bytes([0x37; AUTH_TAG_LENGTH]);
        let protected = protect_endpoint_key(&key, INSTALL_ID).expect("protect");
        let recovered = unprotect_endpoint_key(&protected, INSTALL_ID).expect("unprotect");
        assert!(recovered.secret_bytes() == key.secret_bytes());

        let wrong = "1123456789abcdef0123456789abcdef";
        assert!(unprotect_endpoint_key(&protected, wrong).is_err());
        let mut tampered = protected.as_bytes().to_vec();
        let index = tampered.len() / 2;
        tampered[index] ^= 1;
        let tampered = ProtectedEndpointKey::from_bytes(tampered).expect("bounded");
        assert!(unprotect_endpoint_key(&tampered, INSTALL_ID).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn dpapi_unprotect_requires_exactly_32_plaintext_bytes() {
        for length in [0, AUTH_TAG_LENGTH - 1, AUTH_TAG_LENGTH + 1] {
            let plaintext = vec![0x31; length];
            let protected = platform::protect_arbitrary_for_test(&plaintext, INSTALL_ID);
            assert_eq!(
                unprotect_endpoint_key(&protected, INSTALL_ID)
                    .expect_err("wrong plaintext length")
                    .code(),
                NativeErrorCode::SecretInvalid
            );
        }
    }
}
