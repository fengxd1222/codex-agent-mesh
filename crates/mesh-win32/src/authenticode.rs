//! Offline Authenticode admission for executable artifacts.
//!
//! Official admission combines Windows' Authenticode policy with an exact
//! SHA-256 pin of the leaf signing certificate's DER encoding. The certificate
//! pin is deliberately stronger and less ambiguous than a localized publisher
//! display name. Certificate rotation therefore requires an explicit pin
//! update in the release manifest.
//!
//! Verification never displays UI or retrieves certificates/revocation data
//! from the network. Revocation is checked only against the local Windows cache;
//! a missing or stale cached response can consequently reject an otherwise
//! valid signature. The input must be an absolute local fixed-drive path to a
//! nonempty regular, non-reparse file no larger than
//! [`MAX_AUTHENTICODE_FILE_BYTES`]. The final file is held without write/delete
//! sharing while Windows verifies it. Containment and ancestor reparse checks
//! remain the responsibility of the caller's validated-root boundary.

use std::path::Path;

use crate::{NativeError, NativeErrorCode, NativeOperation};

/// Maximum executable size accepted by the Authenticode boundary (512 MiB).
///
/// This bounds local parsing and hashing work before invoking the Windows trust
/// provider. Release artifacts larger than this limit require a reviewed
/// contract change rather than an implicit resource increase.
pub const MAX_AUTHENTICODE_FILE_BYTES: u64 = 512 * 1024 * 1024;

/// Explicit admission policy for one executable artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticodePolicy {
    /// Require Windows trust and the exact leaf signing-certificate identity.
    Official {
        /// SHA-256 of the complete DER-encoded leaf signing certificate.
        expected_signer_certificate_sha256: [u8; 32],
    },
    /// Admit only a file for which Windows reports no embedded signature.
    ///
    /// This policy is an explicit development-only downgrade. A trusted,
    /// malformed, invalid, or untrusted signature does not satisfy it.
    UnsignedDevelopment,
}

/// Successful Authenticode admission result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticodeVerification {
    /// Windows trusted the signature and the leaf certificate matched the pin.
    OfficialSigned {
        /// SHA-256 of the complete DER-encoded leaf signing certificate.
        signer_certificate_sha256: [u8; 32],
    },
    /// The file was admitted only through the explicit unsigned-development
    /// policy and must never be represented as an official release artifact.
    UnsignedDevelopment,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TrustEvidence {
    Trusted { signer_certificate_sha256: [u8; 32] },
    NoEmbeddedSignature,
    Rejected(u32),
}

/// Verify an executable against an explicit Authenticode admission policy.
///
/// Official verification uses `WINTRUST_ACTION_GENERIC_VERIFY_V2`, disables all
/// trust UI and network retrieval, performs cache-only revocation checking for
/// the chain excluding its root, and pins the primary leaf signing certificate
/// by SHA-256 over its exact DER bytes. Any unsigned, invalid, revoked,
/// untrusted, or signer-mismatched artifact fails closed.
///
/// `UnsignedDevelopment` succeeds only when Windows returns
/// `TRUST_E_NOSIGNATURE`; it produces a distinct result variant and can never
/// produce `OfficialSigned`.
///
/// # Errors
///
/// Returns only redaction-safe [`NativeError`] labels. Caller paths,
/// certificate names, and certificate bytes are never placed in an error.
pub fn verify_authenticode(
    path: &Path,
    policy: AuthenticodePolicy,
) -> Result<AuthenticodeVerification, NativeError> {
    if let AuthenticodePolicy::Official {
        expected_signer_certificate_sha256,
    } = policy
        && expected_signer_certificate_sha256 == [0; 32]
    {
        return Err(invalid_policy());
    }

    platform::verify(path, policy)
}

fn apply_policy(
    policy: AuthenticodePolicy,
    evidence: TrustEvidence,
) -> Result<AuthenticodeVerification, NativeError> {
    match (policy, evidence) {
        (
            AuthenticodePolicy::Official {
                expected_signer_certificate_sha256,
            },
            TrustEvidence::Trusted {
                signer_certificate_sha256,
            },
        ) if expected_signer_certificate_sha256 == signer_certificate_sha256 => {
            Ok(AuthenticodeVerification::OfficialSigned {
                signer_certificate_sha256,
            })
        }
        (AuthenticodePolicy::UnsignedDevelopment, TrustEvidence::NoEmbeddedSignature) => {
            Ok(AuthenticodeVerification::UnsignedDevelopment)
        }
        (_, TrustEvidence::Rejected(status)) => Err(NativeError::with_os_code(
            NativeErrorCode::AuthenticationFailed,
            NativeOperation::VerifyAuthenticode,
            status,
        )),
        _ => Err(authentication_failed()),
    }
}

const fn invalid_policy() -> NativeError {
    NativeError::new(
        NativeErrorCode::InvalidArgument,
        NativeOperation::VerifyAuthenticode,
    )
}

const fn authentication_failed() -> NativeError {
    NativeError::new(
        NativeErrorCode::AuthenticationFailed,
        NativeOperation::VerifyAuthenticode,
    )
}

#[cfg(windows)]
mod platform {
    use std::ffi::c_void;
    use std::mem::size_of;
    use std::os::windows::ffi::OsStrExt;
    use std::path::{Path, Prefix};
    use std::ptr;
    use std::slice;

    use sha2::{Digest, Sha256};
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_ACCESS_DENIED, GENERIC_READ, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Security::WinTrust::{
        WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_FILE_INFO,
        WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE, WTD_DISABLE_MD2_MD4,
        WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE,
        WTD_STATEACTION_VERIFY, WTD_UI_NONE, WTHelperGetProvCertFromChain,
        WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData, WinVerifyTrust,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_ATTRIBUTE_TAG_INFO, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_TYPE_DISK,
        FileAttributeTagInfo, GetDriveTypeW, GetFileInformationByHandleEx, GetFileSizeEx,
        GetFileType, OPEN_EXISTING,
    };
    use windows_sys::Win32::System::WindowsProgramming::DRIVE_FIXED;
    use windows_sys::core::GUID;

    use super::{
        AuthenticodePolicy, AuthenticodeVerification, MAX_AUTHENTICODE_FILE_BYTES, TrustEvidence,
        apply_policy, invalid_policy,
    };
    use crate::{NativeError, NativeErrorCode, NativeOperation};

    const MAX_PATH_UTF16_UNITS: usize = 32_767;
    const MAX_SIGNER_CERTIFICATE_DER_BYTES: usize = 1024 * 1024;
    const TRUST_E_NOSIGNATURE_STATUS: u32 = 0x800B_0100;

    pub(super) fn verify(
        path: &Path,
        policy: AuthenticodePolicy,
    ) -> Result<AuthenticodeVerification, NativeError> {
        apply_policy(policy, collect_evidence(path)?)
    }

    fn collect_evidence(path: &Path) -> Result<TrustEvidence, NativeError> {
        let (wide_path, drive) = validate_path(path)?;
        ensure_fixed_drive(drive)?;
        let file = open_bounded_regular_file(&wide_path)?;
        let mut trust = WinTrustState::new(wide_path, file);
        let status = trust.verify();
        let evidence = if status == 0 {
            trust.signer_evidence()
        } else if status.cast_unsigned() == TRUST_E_NOSIGNATURE_STATUS {
            Ok(TrustEvidence::NoEmbeddedSignature)
        } else {
            Ok(TrustEvidence::Rejected(status.cast_unsigned()))
        };
        let close_result = trust.close();
        if close_result != 0 {
            return Err(NativeError::with_os_code(
                NativeErrorCode::OsFailure,
                NativeOperation::VerifyAuthenticode,
                close_result.cast_unsigned(),
            ));
        }
        evidence
    }

    #[cfg(test)]
    pub(super) fn inspect_fixture(path: &Path) -> Result<TrustEvidence, NativeError> {
        collect_evidence(path)
    }

    fn validate_path(path: &Path) -> Result<(Vec<u16>, u8), NativeError> {
        if !path.is_absolute() {
            return Err(invalid_policy());
        }
        let drive = match path.components().next() {
            Some(std::path::Component::Prefix(prefix)) => match prefix.kind() {
                Prefix::Disk(drive) | Prefix::VerbatimDisk(drive) => drive,
                _ => return Err(invalid_policy()),
            },
            _ => return Err(invalid_policy()),
        };
        let mut wide_path = Vec::new();
        for unit in path.as_os_str().encode_wide() {
            if unit == 0 || wide_path.len() >= MAX_PATH_UTF16_UNITS - 1 {
                return Err(invalid_policy());
            }
            wide_path.push(unit);
        }
        if wide_path.is_empty() {
            return Err(invalid_policy());
        }
        wide_path.push(0);
        Ok((wide_path, drive))
    }

    fn ensure_fixed_drive(drive: u8) -> Result<(), NativeError> {
        let drive = drive.to_ascii_uppercase();
        if !drive.is_ascii_alphabetic() {
            return Err(invalid_policy());
        }
        let root = [u16::from(drive), u16::from(b':'), u16::from(b'\\'), 0];
        // SAFETY: `root` is a readable NUL-terminated drive-root string.
        let drive_type = unsafe { GetDriveTypeW(root.as_ptr()) };
        if drive_type != DRIVE_FIXED {
            return Err(invalid_policy());
        }
        Ok(())
    }

    fn open_bounded_regular_file(wide_path: &[u16]) -> Result<OwnedHandle, NativeError> {
        // SAFETY: `wide_path` is a validated NUL-terminated UTF-16 path. The
        // returned handle is immediately placed under one-owner RAII.
        let handle = unsafe {
            CreateFileW(
                wide_path.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT,
                ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(last_file_error());
        }
        let handle = OwnedHandle(handle);
        // SAFETY: `handle` is a live file handle owned for this scope.
        if unsafe { GetFileType(handle.0) } != FILE_TYPE_DISK {
            return Err(invalid_policy());
        }

        let mut attributes = FILE_ATTRIBUTE_TAG_INFO::default();
        // SAFETY: `attributes` is writable for its exact declared size, and
        // `handle` remains live for the call.
        if unsafe {
            GetFileInformationByHandleEx(
                handle.0,
                FileAttributeTagInfo,
                (&raw mut attributes).cast::<c_void>(),
                u32::try_from(size_of::<FILE_ATTRIBUTE_TAG_INFO>())
                    .expect("FILE_ATTRIBUTE_TAG_INFO size fits u32"),
            )
        } == 0
        {
            return Err(last_file_error());
        }
        if attributes.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)
            != 0
        {
            return Err(invalid_policy());
        }

        let mut file_size = 0_i64;
        // SAFETY: `file_size` is writable and `handle` remains live.
        if unsafe { GetFileSizeEx(handle.0, &raw mut file_size) } == 0 {
            return Err(last_file_error());
        }
        if file_size <= 0
            || u64::try_from(file_size).map_or(true, |size| size > MAX_AUTHENTICODE_FILE_BYTES)
        {
            return Err(invalid_policy());
        }
        Ok(handle)
    }

    struct WinTrustState {
        action: GUID,
        data: Box<WINTRUST_DATA>,
        _file_info: Box<WINTRUST_FILE_INFO>,
        _wide_path: Vec<u16>,
        _file: OwnedHandle,
        verify_called: bool,
    }

    impl WinTrustState {
        fn new(wide_path: Vec<u16>, file: OwnedHandle) -> Self {
            let mut file_info = Box::new(WINTRUST_FILE_INFO {
                cbStruct: u32::try_from(size_of::<WINTRUST_FILE_INFO>())
                    .expect("WINTRUST_FILE_INFO size fits u32"),
                pcwszFilePath: wide_path.as_ptr(),
                hFile: file.0,
                pgKnownSubject: ptr::null_mut(),
            });
            let data = Box::new(WINTRUST_DATA {
                cbStruct: u32::try_from(size_of::<WINTRUST_DATA>())
                    .expect("WINTRUST_DATA size fits u32"),
                pPolicyCallbackData: ptr::null_mut(),
                pSIPClientData: ptr::null_mut(),
                dwUIChoice: WTD_UI_NONE,
                // The provider flag below selects chain revocation excluding
                // the root; keep this legacy field neutral to avoid asking a
                // second, conflicting whole-chain (including root) check.
                fdwRevocationChecks: WTD_REVOKE_NONE,
                dwUnionChoice: WTD_CHOICE_FILE,
                Anonymous: windows_sys::Win32::Security::WinTrust::WINTRUST_DATA_0 {
                    pFile: &raw mut *file_info,
                },
                dwStateAction: WTD_STATEACTION_VERIFY,
                hWVTStateData: ptr::null_mut(),
                pwszURLReference: ptr::null_mut(),
                dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL
                    | WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT
                    | WTD_DISABLE_MD2_MD4,
                dwUIContext: 0,
                pSignatureSettings: ptr::null_mut(),
            });
            Self {
                action: WINTRUST_ACTION_GENERIC_VERIFY_V2,
                data,
                _file_info: file_info,
                _wide_path: wide_path,
                _file: file,
                verify_called: false,
            }
        }

        fn verify(&mut self) -> i32 {
            self.verify_called = true;
            // SAFETY: all nested pointers in `data` point to heap allocations
            // owned by `self` for the full call/state lifetime. UI is disabled.
            unsafe {
                WinVerifyTrust(
                    ptr::null_mut(),
                    &raw mut self.action,
                    (&raw mut *self.data).cast::<c_void>(),
                )
            }
        }

        fn signer_evidence(&mut self) -> Result<TrustEvidence, NativeError> {
            if self.data.hWVTStateData.is_null() {
                return Err(super::authentication_failed());
            }
            // SAFETY: a successful VERIFY call owns live state until CLOSE.
            let provider = unsafe { WTHelperProvDataFromStateData(self.data.hWVTStateData) };
            if provider.is_null() {
                return Err(super::authentication_failed());
            }
            // SAFETY: `provider` belongs to the live WinTrust state. Index zero
            // selects the primary signer, never a countersigner.
            let signer = unsafe { WTHelperGetProvSignerFromChain(provider, 0, 0, 0) };
            if signer.is_null() {
                return Err(super::authentication_failed());
            }
            // SAFETY: `signer` belongs to the live state; index zero is the leaf
            // signing certificate in the verified primary chain.
            let provider_certificate = unsafe { WTHelperGetProvCertFromChain(signer, 0) };
            if provider_certificate.is_null() {
                return Err(super::authentication_failed());
            }
            // SAFETY: the provider certificate is owned by the live state.
            let certificate = unsafe { (*provider_certificate).pCert };
            if certificate.is_null() {
                return Err(super::authentication_failed());
            }
            // SAFETY: `certificate` is owned by the live state.
            let encoded_length = unsafe { (*certificate).cbCertEncoded as usize };
            // SAFETY: `certificate` is owned by the live state.
            let encoded = unsafe { (*certificate).pbCertEncoded };
            if encoded.is_null()
                || encoded_length == 0
                || encoded_length > MAX_SIGNER_CERTIFICATE_DER_BYTES
            {
                return Err(super::authentication_failed());
            }
            // SAFETY: CERT_CONTEXT guarantees `pbCertEncoded` is readable for
            // `cbCertEncoded` bytes while the provider state is live; the
            // length was independently bounded above.
            let certificate_der = unsafe { slice::from_raw_parts(encoded, encoded_length) };
            Ok(TrustEvidence::Trusted {
                signer_certificate_sha256: Sha256::digest(certificate_der).into(),
            })
        }

        fn close(&mut self) -> i32 {
            if !self.verify_called {
                return 0;
            }
            self.data.dwStateAction = WTD_STATEACTION_CLOSE;
            // Set the flag before the call so Drop never double-closes even if
            // the provider reports a close error.
            self.verify_called = false;
            // SAFETY: this is the documented matching CLOSE for the previous
            // VERIFY call, with all nested allocations still alive.
            unsafe {
                WinVerifyTrust(
                    ptr::null_mut(),
                    &raw mut self.action,
                    (&raw mut *self.data).cast::<c_void>(),
                )
            }
        }
    }

    impl Drop for WinTrustState {
        fn drop(&mut self) {
            let _ = self.close();
        }
    }

    struct OwnedHandle(HANDLE);

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            // SAFETY: this wrapper owns one valid CreateFileW handle exactly
            // once. CloseHandle has no additional lifetime requirements.
            unsafe { CloseHandle(self.0) };
        }
    }

    fn last_file_error() -> NativeError {
        // SAFETY: GetLastError has no input and reads thread-local error state
        // immediately after the failed Win32 operation.
        let status = unsafe { GetLastError() };
        NativeError::with_os_code(
            if status == ERROR_ACCESS_DENIED {
                NativeErrorCode::AccessDenied
            } else {
                NativeErrorCode::OsFailure
            },
            NativeOperation::VerifyAuthenticode,
            status,
        )
    }
}

#[cfg(not(windows))]
mod platform {
    use std::path::Path;

    use super::{AuthenticodePolicy, AuthenticodeVerification};
    use crate::{NativeError, NativeErrorCode, NativeOperation};

    pub(super) fn verify(
        _path: &Path,
        _policy: AuthenticodePolicy,
    ) -> Result<AuthenticodeVerification, NativeError> {
        Err(NativeError::new(
            NativeErrorCode::UnsupportedPlatform,
            NativeOperation::VerifyAuthenticode,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXPECTED: [u8; 32] = [0x11; 32];
    const OTHER: [u8; 32] = [0x22; 32];

    #[test]
    fn official_policy_requires_trust_and_the_exact_certificate_pin() {
        assert_eq!(
            apply_policy(
                AuthenticodePolicy::Official {
                    expected_signer_certificate_sha256: EXPECTED,
                },
                TrustEvidence::Trusted {
                    signer_certificate_sha256: EXPECTED,
                },
            )
            .expect("matching trusted signer"),
            AuthenticodeVerification::OfficialSigned {
                signer_certificate_sha256: EXPECTED,
            }
        );

        let mismatch = apply_policy(
            AuthenticodePolicy::Official {
                expected_signer_certificate_sha256: EXPECTED,
            },
            TrustEvidence::Trusted {
                signer_certificate_sha256: OTHER,
            },
        )
        .expect_err("mismatched signer");
        assert_eq!(mismatch.code(), NativeErrorCode::AuthenticationFailed);
        assert_eq!(mismatch.os_code(), None);

        let unsigned = apply_policy(
            AuthenticodePolicy::Official {
                expected_signer_certificate_sha256: EXPECTED,
            },
            TrustEvidence::NoEmbeddedSignature,
        )
        .expect_err("unsigned official artifact");
        assert_eq!(unsigned.code(), NativeErrorCode::AuthenticationFailed);
    }

    #[test]
    fn unsigned_development_is_a_distinct_non_official_result() {
        assert_eq!(
            apply_policy(
                AuthenticodePolicy::UnsignedDevelopment,
                TrustEvidence::NoEmbeddedSignature,
            )
            .expect("explicit unsigned development"),
            AuthenticodeVerification::UnsignedDevelopment
        );

        let trusted = apply_policy(
            AuthenticodePolicy::UnsignedDevelopment,
            TrustEvidence::Trusted {
                signer_certificate_sha256: EXPECTED,
            },
        )
        .expect_err("a signed artifact is not unsigned development");
        assert_eq!(trusted.code(), NativeErrorCode::AuthenticationFailed);
    }

    #[test]
    fn rejected_trust_status_is_preserved_without_sensitive_context() {
        let status = 0x800B_010C;
        let error = apply_policy(
            AuthenticodePolicy::Official {
                expected_signer_certificate_sha256: EXPECTED,
            },
            TrustEvidence::Rejected(status),
        )
        .expect_err("revoked signer");
        assert_eq!(error.code(), NativeErrorCode::AuthenticationFailed);
        assert_eq!(error.operation(), NativeOperation::VerifyAuthenticode);
        assert_eq!(error.os_code(), Some(status));
        assert!(!error.to_string().contains("publisher"));
    }

    #[test]
    fn all_zero_official_pin_is_rejected_before_platform_access() {
        let error = verify_authenticode(
            Path::new("ignored"),
            AuthenticodePolicy::Official {
                expected_signer_certificate_sha256: [0; 32],
            },
        )
        .expect_err("zero pin");
        assert_eq!(error.code(), NativeErrorCode::InvalidArgument);
    }

    #[cfg(windows)]
    #[test]
    fn unsigned_test_executable_is_admitted_only_as_development() {
        let executable = std::env::current_exe().expect("current test executable");
        assert_eq!(
            verify_authenticode(&executable, AuthenticodePolicy::UnsignedDevelopment)
                .expect("unsigned development fixture"),
            AuthenticodeVerification::UnsignedDevelopment
        );

        let official = verify_authenticode(
            &executable,
            AuthenticodePolicy::Official {
                expected_signer_certificate_sha256: EXPECTED,
            },
        )
        .expect_err("an unsigned test executable is never an official fixture");
        assert_eq!(official.code(), NativeErrorCode::AuthenticationFailed);
    }

    #[cfg(windows)]
    #[test]
    fn relative_paths_are_rejected_before_file_access() {
        let error = verify_authenticode(
            Path::new("relative.exe"),
            AuthenticodePolicy::UnsignedDevelopment,
        )
        .expect_err("relative path");
        assert_eq!(error.code(), NativeErrorCode::InvalidArgument);
    }

    #[cfg(windows)]
    #[test]
    fn optional_real_signed_fixture_matches_explicit_certificate_pin() {
        let Some(path) = std::env::var_os("MESH_AUTHENTICODE_SIGNED_FIXTURE") else {
            return;
        };
        let expected_hex = std::env::var("MESH_AUTHENTICODE_SIGNER_SHA256")
            .expect("signed fixture requires MESH_AUTHENTICODE_SIGNER_SHA256");
        assert_eq!(expected_hex.len(), 64, "expected exact lower hex64 pin");
        assert!(
            expected_hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "expected exact lower hex64 pin"
        );
        let decoded = data_encoding::HEXLOWER
            .decode(expected_hex.as_bytes())
            .expect("lower hex64 signer pin");
        let expected: [u8; 32] = decoded.try_into().expect("32-byte signer pin");

        let evidence = platform::inspect_fixture(Path::new(&path)).expect("signed fixture trust");
        assert_eq!(
            evidence,
            TrustEvidence::Trusted {
                signer_certificate_sha256: expected,
            },
            "fixture pin must identify the primary Authenticode leaf certificate"
        );

        assert_eq!(
            verify_authenticode(
                Path::new(&path),
                AuthenticodePolicy::Official {
                    expected_signer_certificate_sha256: expected,
                },
            )
            .expect("official signed fixture"),
            AuthenticodeVerification::OfficialSigned {
                signer_certificate_sha256: expected,
            }
        );

        let mut mismatched = expected;
        mismatched[0] ^= 1;
        let error = verify_authenticode(
            Path::new(&path),
            AuthenticodePolicy::Official {
                expected_signer_certificate_sha256: mismatched,
            },
        )
        .expect_err("real signed fixture must reject a mismatched pin");
        assert_eq!(error.code(), NativeErrorCode::AuthenticationFailed);
    }
}
