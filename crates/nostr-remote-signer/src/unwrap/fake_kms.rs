//! A stand-in for AWS KMS: its JSON API over plain HTTP, under the key policy of D2-4 —
//! `Encrypt` for anyone, `Decrypt` for an attested enclave only, and only for the image
//! `pcr0` when one is set.
//!
//! For the tests, and for the vault under QEMU, whose attestation documents AWS has not
//! signed. It protects nothing: its `Encrypt` is the identity, and it does not check the
//! document's signature. Dev identities only.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use super::recipient::testing::seal_for;
use crate::cbor::Cbor;

/// A SHA-384 measurement.
pub type Pcr = [u8; 48];

/// A PCR in hex, as `nitro-cli` prints it.
pub fn parse_pcr(hex: &str) -> Option<Pcr> {
    let bytes = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(hex.get(i..i + 2)?, 16).ok())
        .collect::<Option<Vec<_>>>()?;
    bytes.try_into().ok()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Answers KMS calls on `listener` until it fails.
pub async fn serve(listener: TcpListener, pcr0: Option<Pcr>) {
    while let Ok((stream, _)) = listener.accept().await {
        tokio::spawn(connection(stream, pcr0));
    }
}

/// HTTP/1.1 as the AWS SDK speaks it: a `content-length` body, several requests per
/// connection.
async fn connection(stream: TcpStream, pcr0: Option<Pcr>) {
    let mut stream = BufReader::new(stream);
    loop {
        let (mut target, mut len) = (String::new(), 0);
        loop {
            let mut line = String::new();
            if stream.read_line(&mut line).await.unwrap_or(0) == 0 {
                return;
            }
            let line = line.trim_end();
            if line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                match name.to_ascii_lowercase().as_str() {
                    "x-amz-target" => target = value.trim().to_string(),
                    "content-length" => len = value.trim().parse().unwrap_or(0),
                    _ => {}
                }
            }
        }
        let mut body = vec![0; len];
        if stream.read_exact(&mut body).await.is_err() {
            return;
        }

        let request = serde_json::from_slice(&body).unwrap_or(Value::Null);
        let (status, reply) = answer(&target, &request, pcr0);
        let reply = reply.to_string();
        let head = format!(
            "HTTP/1.1 {status}\r\ncontent-type: application/x-amz-json-1.1\r\n\
             content-length: {}\r\n\r\n",
            reply.len()
        );
        let stream = stream.get_mut();
        if stream.write_all(head.as_bytes()).await.is_err()
            || stream.write_all(reply.as_bytes()).await.is_err()
        {
            return;
        }
    }
}

fn answer(target: &str, request: &Value, pcr0: Option<Pcr>) -> (&'static str, Value) {
    match target {
        "TrentService.Encrypt" => (
            "200 OK",
            json!({ "CiphertextBlob": request["Plaintext"], "KeyId": request["KeyId"] }),
        ),
        "TrentService.Decrypt" => match decrypt(request, pcr0) {
            Ok(answer) => (
                "200 OK",
                json!({
                    "CiphertextForRecipient": BASE64.encode(answer),
                    "KeyId": request["KeyId"],
                }),
            ),
            Err(why) => {
                tracing::warn!("Decrypt denied: {why}");
                let error = json!({ "__type": "AccessDeniedException", "message": why });
                ("400 Bad Request", error)
            }
        },
        other => {
            let error = json!({ "__type": "UnsupportedOperationException", "message": other });
            ("400 Bad Request", error)
        }
    }
}

/// The plaintext, sealed for the enclave that attests, if the key policy admits it.
fn decrypt(request: &Value, pcr0: Option<Pcr>) -> Result<Vec<u8>, String> {
    let blob = |field: &Value| field.as_str().and_then(|b| BASE64.decode(b).ok());
    let recipient = &request["Recipient"];
    if recipient.is_null() {
        return Err("no attestation document".into());
    }
    if recipient["KeyEncryptionAlgorithm"] != "RSAES_OAEP_SHA_256" {
        return Err("unexpected key encryption algorithm".into());
    }
    let document = blob(&recipient["AttestationDocument"]).unwrap_or_default();
    let (public_key, measured) =
        read_document(&document).ok_or("unreadable attestation document")?;
    if let Some(expected) = pcr0
        && measured != expected
    {
        return Err(format!(
            "the key policy admits PCR0 {}, not {}",
            hex(&expected),
            hex(measured)
        ));
    }
    let plaintext = blob(&request["CiphertextBlob"]).ok_or("no CiphertextBlob")?;
    let answer = seal_for(public_key, &plaintext).ok_or("the public key is not RSA")?;
    tracing::info!("Decrypt released to PCR0 {}", hex(measured));
    Ok(answer)
}

/// The public key and PCR0 of an attestation document: COSE_Sign1, whose payload is a
/// CBOR map. The signature is not checked.
fn read_document(document: &[u8]) -> Option<(&[u8], &[u8])> {
    let cose = match Cbor::parse(document)? {
        Cbor::Tag(18, cose) => *cose,
        cose => cose,
    };
    let Cbor::Array(cose) = cose else {
        return None;
    };
    let [_, _, payload, _] = cose.as_slice() else {
        return None;
    };
    let payload = Cbor::parse(payload.bytes()?)?;
    let Some(Cbor::Map(pcrs)) = payload.get("pcrs") else {
        return None;
    };
    let pcr0 = pcrs
        .iter()
        .find_map(|(index, pcr)| (*index == Cbor::Unsigned(0)).then_some(pcr))?;
    Some((payload.get("public_key")?.bytes()?, pcr0.bytes()?))
}

/// An attestation document laid out as QEMU's NSM lays it out, without the fields the
/// fake does not read.
#[cfg(test)]
pub(crate) fn document(public_key: &[u8], pcr0: &Pcr) -> Vec<u8> {
    use crate::cbor::{ARRAY, MAP, write_bytes, write_head, write_text};

    let mut payload = Vec::new();
    write_head(&mut payload, MAP, 2);
    write_text(&mut payload, "pcrs");
    write_head(&mut payload, MAP, 1);
    write_head(&mut payload, 0, 0);
    write_bytes(&mut payload, pcr0);
    write_text(&mut payload, "public_key");
    write_bytes(&mut payload, public_key);

    let mut document = Vec::new();
    write_head(&mut document, ARRAY, 4);
    // Protected header {1: -1}, no signature: QEMU does not sign either.
    write_bytes(&mut document, &[0xa1, 0x01, 0x20]);
    write_head(&mut document, MAP, 0);
    write_bytes(&mut document, &payload);
    write_bytes(&mut document, &[0; 64]);
    document
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_public_key_and_the_measurement() {
        let document = document(&[1; 294], &[7; 48]);
        let expected = Some((&[1; 294][..], &[7; 48][..]));
        assert_eq!(read_document(&document), expected);
        assert_eq!(read_document(&[&[0xd2], &document[..]].concat()), expected);
        assert_eq!(read_document(&document[..document.len() - 1]), None);
    }

    #[test]
    fn parses_a_pcr_as_nitro_cli_prints_it() {
        assert_eq!(parse_pcr(&"07".repeat(48)), Some([7; 48]));
        assert_eq!(parse_pcr(&"07".repeat(32)), None);
        assert_eq!(parse_pcr(&"0g".repeat(48)), None);
        assert_eq!(parse_pcr("0é"), None);
    }
}
