//! The Nitro Secure Module: the enclave's attestation documents.
//!
//! One request, `Attestation`, through an ioctl on `/dev/nsm`. Request and response are
//! CBOR, in the layout of AWS's `aws-nitro-enclaves-nsm-api`. The document that comes back
//! is signed by the Nitro hypervisor and carries the enclave's PCRs and our public key.

#[cfg(target_os = "linux")]
pub use linux::Nsm;
use nostr_remote_signer_core::KeyUnwrapError;

use crate::cbor::{self, Cbor, MAP, NULL};

/// `{"Attestation": {"user_data": null, "nonce": null, "public_key": h'…'}}`
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn attestation_request(public_key: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    cbor::write_head(&mut out, MAP, 1);
    cbor::write_text(&mut out, "Attestation");
    cbor::write_head(&mut out, MAP, 3);
    cbor::write_text(&mut out, "user_data");
    out.push(NULL);
    cbor::write_text(&mut out, "nonce");
    out.push(NULL);
    cbor::write_text(&mut out, "public_key");
    cbor::write_bytes(&mut out, public_key);
    out
}

/// `{"Attestation": {"document": h'…'}}`, or `{"Error": "…"}`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn attestation_document(response: &[u8]) -> Result<Vec<u8>, KeyUnwrapError> {
    let response = Cbor::parse(response)
        .ok_or_else(|| KeyUnwrapError::Backend("malformed NSM response".into()))?;
    if let Some(document) = response
        .get("Attestation")
        .and_then(|a| a.get("document"))
        .and_then(Cbor::bytes)
    {
        return Ok(document.to_vec());
    }
    let error = response
        .get("Error")
        .and_then(Cbor::text)
        .unwrap_or("unexpected response");
    Err(KeyUnwrapError::Backend(format!("NSM: {error}")))
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs::OpenOptions;
    use std::io;
    use std::os::fd::AsRawFd;

    use nostr_remote_signer_core::KeyUnwrapError;

    use super::{attestation_document, attestation_request};
    use crate::unwrap::kms::Attester;

    const DEVICE: &str = "/dev/nsm";
    /// The driver's limit for a response.
    const RESPONSE_MAX: usize = 0x3000;

    #[repr(C)]
    struct Message {
        request: libc::iovec,
        response: libc::iovec,
    }

    /// `_IOWR(0x0A, 0, struct nsm_message)`
    const IOCTL: u64 = 0xc000_0000 | ((size_of::<Message>() as u64) << 16) | (0x0a << 8);

    #[derive(Debug)]
    pub struct Nsm;

    impl Attester for Nsm {
        fn attest(&self, public_key: &[u8]) -> Result<Vec<u8>, KeyUnwrapError> {
            let failed = |e: io::Error| KeyUnwrapError::Backend(format!("{DEVICE}: {e}"));
            let device = OpenOptions::new()
                .read(true)
                .write(true)
                .open(DEVICE)
                .map_err(failed)?;

            let request = attestation_request(public_key);
            let mut response = vec![0u8; RESPONSE_MAX];
            let mut message = Message {
                request: libc::iovec {
                    iov_base: request.as_ptr() as *mut libc::c_void,
                    iov_len: request.len(),
                },
                response: libc::iovec {
                    iov_base: response.as_mut_ptr().cast(),
                    iov_len: response.len(),
                },
            };
            // SAFETY: the driver reads `request` and writes at most `response.len()` bytes
            // into `response`, both alive for the whole call, then sets the length written.
            let rc = unsafe { libc::ioctl(device.as_raw_fd(), IOCTL as _, &mut message) };
            if rc != 0 {
                return Err(failed(io::Error::last_os_error()));
            }
            response.truncate(message.response.iov_len);
            attestation_document(&response)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Bytes produced by `aws-nitro-enclaves-nsm-api` 0.5.2 (serde_cbor) for the same values.
    const REQUEST: &str = "a16b4174746573746174696f6ea369757365725f64617461f6656e6f6e6365f66a7075626c69635f6b6579\
                           43010203";
    const RESPONSE: &str = "a16b4174746573746174696f6ea168646f63756d656e74450909090909";
    const ERROR: &str = "a1654572726f726f496e76616c6964417267756d656e74";

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn the_request_is_laid_out_as_the_nsm_expects() {
        assert_eq!(attestation_request(&[1, 2, 3]), hex(REQUEST));
    }

    #[test]
    fn the_document_comes_out_of_the_response() {
        assert_eq!(attestation_document(&hex(RESPONSE)).unwrap(), [9; 5]);
    }

    #[test]
    fn an_nsm_error_is_reported() {
        let err = attestation_document(&hex(ERROR)).unwrap_err();
        assert_eq!(
            err.to_string(),
            "key unwrapper backend: NSM: InvalidArgument"
        );
        assert!(attestation_document(&[0xa1]).is_err());
    }
}
