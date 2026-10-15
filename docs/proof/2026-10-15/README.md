# Attested key release on AWS Nitro Enclaves, 2026-10-15

An EC2 `m5.xlarge` in `eu-west-3` as the parent instance, the vault in a Nitro Enclave, a
dev identity. The account ID is masked as `111122223333`, and so is the operator's name in
`cloudtrail.json`. The key, the instance and the role were deleted after the session.

| File | What it is |
|---|---|
| `transcript.txt` | The terminal on the parent instance, recorded with `script`, terminal escape codes removed. Root is refused; the image is refused in debug mode; the image without debug opens its keys and an agent gets an event signed |
| `key-policy.json` | The key policy in force during the session, read back from KMS |
| `pcrs.json` | The image's measurements, from `nitro-cli build-enclave` |
| `cloudtrail.json` | The `Decrypt` calls on the key that CloudTrail recorded, condensed with `jq`: time, caller, user agent, error, image digest |

## What to compare

- **One PCR0, three sources.** PCR0 in `pcrs.json` is the
  `kms:RecipientAttestation:ImageSha384` of `key-policy.json`, and the `image` of the two
  successful calls in `cloudtrail.json`, one per sealed key. CloudTrail gives it in base64:
  `echo '<image>' | base64 -d | xxd -p -c 48`.
- **Every other call is refused.** In `cloudtrail.json`: root on the parent instance
  (`aws-cli`), the same image in debug mode (`aws-sdk-rust`; no image was recorded for this
  refused call), and an administrator of the account (`aws-cli`).
- **No one else may decrypt.** In `key-policy.json`, the account administers the key and
  may encrypt with it; only the instance's role may decrypt, and only with that PCR0.

The scripts that created the key, its policy and the instance are in
[`enclave/aws/`](../../../enclave/aws/).
