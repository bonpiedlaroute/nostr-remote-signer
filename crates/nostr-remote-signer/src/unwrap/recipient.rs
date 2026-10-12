//! The enclave's side of an attested KMS call.
//!
//! The enclave puts a fresh RSA public key in its attestation document. KMS then answers
//! with `CiphertextForRecipient` instead of the plaintext: a CMS EnvelopedData (RFC 5652)
//! whose content key is wrapped for that public key with RSAES-OAEP-SHA-256, and whose
//! content is encrypted with AES-256-CBC. Only the enclave holds the private key.
//!
//! KMS encodes it in BER, with indefinite lengths and the content in chunks: a strict DER
//! decoder rejects every real answer. Hence the small BER reader below.

use aws_lc_rs::cipher::{AES_256, DecryptionContext, PaddedBlockDecryptingKey, UnboundCipherKey};
use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::iv::FixedLength;
use aws_lc_rs::rsa::{
    KeySize, OAEP_SHA256_MGF1SHA256, OaepPrivateDecryptingKey, PrivateDecryptingKey,
};
use nostr_remote_signer_core::KeyUnwrapError;
use zeroize::Zeroizing;

/// An RSA key pair for one attested KMS call. The private key never leaves this value.
#[derive(Debug)]
pub struct Recipient {
    key: OaepPrivateDecryptingKey,
    public_key: Vec<u8>,
}

impl Recipient {
    pub fn generate() -> Result<Self, KeyUnwrapError> {
        let failed = |_| KeyUnwrapError::Backend("cannot generate the recipient key".into());
        let private = PrivateDecryptingKey::generate(KeySize::Rsa2048).map_err(failed)?;
        let public_key = private
            .public_key()
            .as_der()
            .map_err(failed)?
            .as_ref()
            .to_vec();
        let key = OaepPrivateDecryptingKey::new(private).map_err(failed)?;
        Ok(Self { key, public_key })
    }

    /// SubjectPublicKeyInfo, DER: what the attestation document carries.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// The plaintext of a `CiphertextForRecipient` sealed for this key.
    pub fn open(&self, answer: &[u8]) -> Result<Zeroizing<Vec<u8>>, KeyUnwrapError> {
        let envelope = Envelope::parse(answer)
            .ok_or_else(|| KeyUnwrapError::Backend("malformed CiphertextForRecipient".into()))?;

        let mut content_key = Zeroizing::new(vec![0; self.key.min_output_size()]);
        let content_key = self
            .key
            .decrypt(
                &OAEP_SHA256_MGF1SHA256,
                envelope.encrypted_key,
                &mut content_key,
                None,
            )
            .map_err(|_| KeyUnwrapError::Invalid)?;
        let cipher = UnboundCipherKey::new(&AES_256, content_key)
            .and_then(PaddedBlockDecryptingKey::cbc_pkcs7)
            .map_err(|_| KeyUnwrapError::Invalid)?;

        let mut plaintext = Zeroizing::new(envelope.content);
        let iv = DecryptionContext::Iv128(FixedLength::from(envelope.iv));
        let len = cipher
            .decrypt(&mut plaintext, iv)
            .map_err(|_| KeyUnwrapError::Invalid)?
            .len();
        plaintext.truncate(len);
        Ok(plaintext)
    }
}

const SEQUENCE: u8 = 0x30;
const SET: u8 = 0x31;
const OID: u8 = 0x06;
const OCTET_STRING: u8 = 0x04;
const CONTEXT_0: u8 = 0xa0;
const CONTEXT_0_PRIMITIVE: u8 = 0x80;

/// 1.2.840.113549.1.7.3
const ENVELOPED_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x03];
/// 1.2.840.113549.1.1.7
const RSAES_OAEP: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x07];
/// 2.16.840.1.101.3.4.1.42
const AES_256_CBC: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a];

/// What the enclave needs from a `CiphertextForRecipient`.
struct Envelope<'a> {
    encrypted_key: &'a [u8],
    iv: [u8; 16],
    content: Vec<u8>,
}

impl<'a> Envelope<'a> {
    fn parse(answer: &'a [u8]) -> Option<Self> {
        let mut input = answer;
        let root = Ber::read(&mut input, 0)?;
        if !input.is_empty() {
            return None;
        }

        // ContentInfo: contentType, [0] EXPLICIT EnvelopedData
        let [content_type, content] = root.children(SEQUENCE)? else {
            return None;
        };
        if content_type.bytes(OID)? != ENVELOPED_DATA {
            return None;
        }
        let [enveloped] = content.children(CONTEXT_0)? else {
            return None;
        };
        // EnvelopedData: version, recipientInfos (SET), encryptedContentInfo (SEQUENCE), and
        // two optional fields with context tags.
        let enveloped = enveloped.children(SEQUENCE)?;
        let [recipient] = enveloped.iter().find_map(|e| e.children(SET))? else {
            return None;
        };
        let content_info = enveloped.iter().find_map(|e| e.children(SEQUENCE))?;

        // KeyTransRecipientInfo: version, rid, keyEncryptionAlgorithm, encryptedKey
        let [_, _, algorithm, encrypted_key] = recipient.children(SEQUENCE)? else {
            return None;
        };
        if algorithm.children(SEQUENCE)?.first()?.bytes(OID)? != RSAES_OAEP {
            return None;
        }

        // EncryptedContentInfo: contentType, contentEncryptionAlgorithm, [0] encryptedContent
        let [_, algorithm, content] = content_info else {
            return None;
        };
        let [cipher, iv] = algorithm.children(SEQUENCE)? else {
            return None;
        };
        if cipher.bytes(OID)? != AES_256_CBC {
            return None;
        }
        let content = match content {
            Ber::Primitive(CONTEXT_0_PRIMITIVE, bytes) => bytes.to_vec(),
            Ber::Constructed(CONTEXT_0, chunks) => chunks
                .iter()
                .map(|chunk| chunk.bytes(OCTET_STRING))
                .collect::<Option<Vec<_>>>()?
                .concat(),
            _ => return None,
        };

        Some(Self {
            encrypted_key: encrypted_key.bytes(OCTET_STRING)?,
            iv: iv.bytes(OCTET_STRING)?.try_into().ok()?,
            content,
        })
    }
}

/// Deep enough for CMS, shallow enough that no answer can exhaust the stack.
const MAX_DEPTH: usize = 16;

/// One BER element: its tag, then its bytes or its children.
enum Ber<'a> {
    Primitive(u8, &'a [u8]),
    Constructed(u8, Vec<Ber<'a>>),
}

impl<'a> Ber<'a> {
    fn read(input: &mut &'a [u8], depth: usize) -> Option<Self> {
        if depth > MAX_DEPTH {
            return None;
        }
        let (&tag, rest) = input.split_first()?;
        // Multi-byte tags never occur in CMS.
        if tag & 0x1f == 0x1f {
            return None;
        }
        let (&first, mut rest) = rest.split_first()?;
        let len = match first {
            0x80 => None,
            n if n < 0x80 => Some(usize::from(n)),
            n => {
                let (bytes, after) = rest.split_at_checked(usize::from(n & 0x7f))?;
                if bytes.len() > 4 {
                    return None;
                }
                rest = after;
                Some(bytes.iter().fold(0, |len, b| len << 8 | usize::from(*b)))
            }
        };

        let element = match (tag & 0x20 != 0, len) {
            (false, Some(len)) => {
                let (bytes, after) = rest.split_at_checked(len)?;
                rest = after;
                Ber::Primitive(tag, bytes)
            }
            (true, Some(len)) => {
                let (mut body, after) = rest.split_at_checked(len)?;
                rest = after;
                let mut children = Vec::new();
                while !body.is_empty() {
                    children.push(Ber::read(&mut body, depth + 1)?);
                }
                Ber::Constructed(tag, children)
            }
            // Indefinite length: children up to the end-of-contents marker.
            (true, None) => {
                let mut children = Vec::new();
                loop {
                    if let Some(after) = rest.strip_prefix(&[0, 0]) {
                        rest = after;
                        break;
                    }
                    children.push(Ber::read(&mut rest, depth + 1)?);
                }
                Ber::Constructed(tag, children)
            }
            (false, None) => return None,
        };
        *input = rest;
        Some(element)
    }

    fn children(&self, tag: u8) -> Option<&[Ber<'a>]> {
        match self {
            Ber::Constructed(t, children) if *t == tag => Some(children),
            _ => None,
        }
    }

    fn bytes(&self, tag: u8) -> Option<&'a [u8]> {
        match self {
            Ber::Primitive(t, bytes) if *t == tag => Some(bytes),
            _ => None,
        }
    }
}

/// KMS's side of an attested `Decrypt`, for the tests of this crate.
#[cfg(test)]
pub(crate) mod testing {
    use aws_lc_rs::cipher::PaddedBlockEncryptingKey;
    use aws_lc_rs::rand::{SecureRandom, SystemRandom};
    use aws_lc_rs::rsa::{OaepPublicEncryptingKey, PublicEncryptingKey};

    use super::*;

    /// The keyEncryptionAlgorithm of both answers: RSAES-OAEP, SHA-256, MGF1 with SHA-256.
    const OAEP_SHA256: &[u8] = &[
        0x30, 0x3c, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x07, 0x30, 0x2f,
        0xa0, 0x0f, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0xa1, 0x1c, 0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
        0x01, 0x08, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00,
    ];
    /// 1.2.840.113549.1.7.1
    const DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01];

    fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        let len = match body.len() {
            n @ 0..0x80 => vec![n as u8],
            n @ 0x80..0x100 => vec![0x81, n as u8],
            n => vec![0x82, (n >> 8) as u8, n as u8],
        };
        [&[tag][..], &len, body].concat()
    }

    fn indefinite(tag: u8, parts: &[&[u8]]) -> Vec<u8> {
        [&[tag, 0x80][..], &parts.concat(), &[0, 0]].concat()
    }

    /// An answer laid out exactly as KMS lays it out.
    pub(crate) fn kms_shaped(
        rid: &[u8],
        encrypted_key: &[u8],
        iv: &[u8],
        chunks: &[&[u8]],
    ) -> Vec<u8> {
        let recipient = tlv(
            SEQUENCE,
            &[
                tlv(0x02, &[2]),
                tlv(CONTEXT_0_PRIMITIVE, rid),
                OAEP_SHA256.to_vec(),
                tlv(OCTET_STRING, encrypted_key),
            ]
            .concat(),
        );
        let chunks: Vec<_> = chunks.iter().map(|c| tlv(OCTET_STRING, c)).collect();
        let chunks: Vec<&[u8]> = chunks.iter().map(Vec::as_slice).collect();
        let algorithm = tlv(
            SEQUENCE,
            &[tlv(OID, AES_256_CBC), tlv(OCTET_STRING, iv)].concat(),
        );
        let content_info = indefinite(
            SEQUENCE,
            &[&tlv(OID, DATA), &algorithm, &indefinite(CONTEXT_0, &chunks)],
        );
        let enveloped = indefinite(
            SEQUENCE,
            &[&tlv(0x02, &[2]), &tlv(SET, &recipient), &content_info],
        );
        indefinite(
            SEQUENCE,
            &[
                &tlv(OID, ENVELOPED_DATA),
                &indefinite(CONTEXT_0, &[&enveloped]),
            ],
        )
    }

    /// What KMS does with an attested Decrypt: a fresh content key wrapped for the
    /// recipient's public key, the plaintext under that key, in two chunks.
    pub(crate) fn seal_for(public_key: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let mut content_key = [0u8; 32];
        SystemRandom::new().fill(&mut content_key).unwrap();

        let public = PublicEncryptingKey::from_der(public_key).unwrap();
        let public = OaepPublicEncryptingKey::new(public).unwrap();
        let mut encrypted_key = vec![0; public.ciphertext_size()];
        let encrypted_key = public
            .encrypt(
                &OAEP_SHA256_MGF1SHA256,
                &content_key,
                &mut encrypted_key,
                None,
            )
            .unwrap();

        let cipher = UnboundCipherKey::new(&AES_256, &content_key).unwrap();
        let cipher = PaddedBlockEncryptingKey::cbc_pkcs7(cipher).unwrap();
        let mut content = plaintext.to_vec();
        let context = cipher.encrypt(&mut content).unwrap();
        let iv: &[u8] = (&context).try_into().unwrap();

        let (first, second) = content.split_at(16);
        kms_shaped(&[7; 32], encrypted_key, iv, &[first, second])
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64;

    use super::testing::{kms_shaped, seal_for};
    use super::*;

    /// Two real KMS answers, from the AWS Nitro Enclaves SDK for C
    /// (tests/kmstool-enclaves/cms_test.c, Apache-2.0): the content in chunks, then the
    /// content in one primitive [0].
    const KMS_CHUNKED: &str = "MIAGCSqGSIb3DQEHA6CAMIACAQIxggFrMIIBZwIBAoAgcIe1XflLoyVc3zwBhAoqo+yTYgYl1gHPVvl73no9LrEwPAYJKoZIhvcNAQEHMC+gDzANBglghkgBZQMEAgEFAKEcMBoGCSqGSIb3DQEBCDANBglghkgBZQMEAgEFAASCAQCgYUWToDDuM2v/8HZhiwEw0EXen00YPYPF2ogvE6vB9L8NE2RYaTk0QqtYLmoE1pfVLVYj42fn6S2269K9B3NbFT8oJr7l344WxxOh6Fy2uoXohoEzXH6UGpSr8MARPgMJFuK24YJttP+5GbjhtvWewnfljeQLD/7sqg2U+8spA3TtPfw10xqPQ64TAP4g/dmG1LhWVldFH53Gk+E0Z4kgIhxYoo2l5xq2sxyqRFglpjhcbE9dXV67wsJXDpZH/e02tVlke8sn5YiGJV9YLGPYY+zsMH0Vdjq84LG4EqVQk4yk4tKKdFY9tSNnVY0+LoKsKif+XJORoAfBX3W5CrDdMIAGCSqGSIb3DQEHATAdBglghkgBZQMEASoEEGiMbV9/MbD+zt8J8ufJmsmggAQwcOXKr/1JrSTv4Vv5A76dGYlbd30mm1ewJfb2fn75P5RGRRXy6+A06gt2IaH/GSkuAAAAAAAAAAAAAA==";
    const KMS_CHUNKED_KEY: &str = "oGFFk6Aw7jNr//B2YYsBMNBF3p9NGD2DxdqILxOrwfS/DRNkWGk5NEKrWC5qBNaX1S1WI+Nn5+kttuvSvQdzWxU/KCa+5d+OFscToehctrqF6IaBM1x+lBqUq/DAET4DCRbituGCbbT/uRm44bb1nsJ35Y3kCw/+7KoNlPvLKQN07T38NdMaj0OuEwD+IP3ZhtS4VlZXRR+dxpPhNGeJICIcWKKNpecatrMcqkRYJaY4XGxPXV1eu8LCVw6WR/3tNrVZZHvLJ+WIhiVfWCxj2GPs7DB9FXY6vOCxuBKlUJOMpOLSinRWPbUjZ1WNPi6CrCon/lyTkaAHwV91uQqw3Q==";
    const KMS_CHUNKED_IV: &str = "aIxtX38xsP7O3wny58mayQ==";
    const KMS_CHUNKED_CONTENT: &str =
        "cOXKr/1JrSTv4Vv5A76dGYlbd30mm1ewJfb2fn75P5RGRRXy6+A06gt2IaH/GSku";
    const KMS_CHUNKED_RID: &str = "cIe1XflLoyVc3zwBhAoqo+yTYgYl1gHPVvl73no9LrE=";

    const KMS_PRIMITIVE: &str = "MIAGCSqGSIb3DQEHA6CAMIACAQIxggFrMIIBZwIBAoAgTmHfaeRDuOJciugzGM/HLZtqUXbSFneQ/fgZwIbmlnowPAYJKoZIhvcNAQEHMC+gDzANBglghkgBZQMEAgEFAKEcMBoGCSqGSIb3DQEBCDANBglghkgBZQMEAgEFAASCAQBKHKEiAuTOCx+LNc6g1dkFM2yqpdUX7tZfb9h6DnspKRJlKUFSepqLiPnnxrUJdAdLgabUN1GHbnyllfVd+GpHQoYZReC5FeS4QLngQ5Ieve+S0ViMcnu6nPk2Cs+WY7yLp9q0Pytho/SRcqB2GACtA2BrWn9ZWUbFCrI8fQAUYp5wwvbUELSWejLgttpxLvg7Hwla1N97DTpYR/mvvXXXKUc6Bw95ecwMQ6HVusd6jtexfbyVTl2IEAMyvA4CwoO/AbTGsWCxFQ6t/I2R1ij19hSvTzhNWB+19gerkfYKw893cyWo+v6QPv8d1+QmAkTlBmSqtiRLw+kZUQcKXcX4MIAGCSqGSIb3DQEHATAdBglghkgBZQMEASoEEOZsEXKu4PL3vjTjr8aw5P6AEB+UPrAQXBsGRN9PcTBEiigAAAAAAAAAAA==";
    const KMS_PRIMITIVE_KEY: &str = "ShyhIgLkzgsfizXOoNXZBTNsqqXVF+7WX2/Yeg57KSkSZSlBUnqai4j558a1CXQHS4Gm1DdRh258pZX1XfhqR0KGGUXguRXkuEC54EOSHr3vktFYjHJ7upz5NgrPlmO8i6fatD8rYaP0kXKgdhgArQNga1p/WVlGxQqyPH0AFGKecML21BC0lnoy4LbacS74Ox8JWtTfew06WEf5r7111ylHOgcPeXnMDEOh1brHeo7XsX28lU5diBADMrwOAsKDvwG0xrFgsRUOrfyNkdYo9fYUr084TVgftfYHq5H2CsPPd3MlqPr+kD7/HdfkJgJE5QZkqrYkS8PpGVEHCl3F+A==";
    const KMS_PRIMITIVE_IV: &str = "5mwRcq7g8ve+NOOvxrDk/g==";
    const KMS_PRIMITIVE_CONTENT: &str = "H5Q+sBBcGwZE309xMESKKA==";

    fn b64(s: &str) -> Vec<u8> {
        BASE64.decode(s).unwrap()
    }

    #[test]
    fn reads_real_kms_answers() {
        for (answer, key, iv, content) in [
            (
                KMS_CHUNKED,
                KMS_CHUNKED_KEY,
                KMS_CHUNKED_IV,
                KMS_CHUNKED_CONTENT,
            ),
            (
                KMS_PRIMITIVE,
                KMS_PRIMITIVE_KEY,
                KMS_PRIMITIVE_IV,
                KMS_PRIMITIVE_CONTENT,
            ),
        ] {
            let answer = b64(answer);
            let envelope = Envelope::parse(&answer).expect("a real KMS answer");
            assert_eq!(envelope.encrypted_key, b64(key));
            assert_eq!(envelope.iv.to_vec(), b64(iv));
            assert_eq!(envelope.content, b64(content));
        }
    }

    #[test]
    fn the_test_answers_are_laid_out_like_kms() {
        let rebuilt = kms_shaped(
            &b64(KMS_CHUNKED_RID),
            &b64(KMS_CHUNKED_KEY),
            &b64(KMS_CHUNKED_IV),
            &[&b64(KMS_CHUNKED_CONTENT)],
        );
        assert_eq!(rebuilt, b64(KMS_CHUNKED));
    }

    #[test]
    fn opens_what_was_sealed_for_it() {
        let recipient = Recipient::generate().unwrap();
        let data_key = [42u8; 32];
        let opened = recipient
            .open(&seal_for(recipient.public_key(), &data_key))
            .unwrap();
        assert_eq!(*opened, data_key);
    }

    #[test]
    fn another_key_cannot_open_it() {
        let recipient = Recipient::generate().unwrap();
        let answer = seal_for(recipient.public_key(), &[42; 32]);
        let other = Recipient::generate().unwrap();
        assert!(matches!(other.open(&answer), Err(KeyUnwrapError::Invalid)));
    }

    #[test]
    fn refuses_what_kms_would_not_send() {
        let answer = b64(KMS_CHUNKED);
        for len in 0..answer.len() {
            assert!(
                Envelope::parse(&answer[..len]).is_none(),
                "truncated at {len}"
            );
        }
        assert!(Envelope::parse(&[answer.as_slice(), &[0]].concat()).is_none());

        let aes_128_cbc = [&AES_256_CBC[..8], &[0x02]].concat();
        let at = answer.windows(9).position(|w| w == AES_256_CBC).unwrap();
        let mut weaker = answer.clone();
        weaker[at..at + 9].copy_from_slice(&aes_128_cbc);
        assert!(Envelope::parse(&weaker).is_none());

        let deep = [0x30, 0x80].repeat(10_000);
        assert!(Envelope::parse(&deep).is_none());
    }
}
