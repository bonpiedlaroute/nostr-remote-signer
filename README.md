# nostr-remote-signer

A NIP-46 remote signer for Nostr agents. The signing key never resides on an
agent host: the host holds only the public key and a credential, the signer holds
the key and applies policy, audit and revocation.

Works with any Nostr relay. Demonstrated against a self-hosted Buzz relay.

## Licensing

This repository is dual-licensed by directory:

| Path | Licence |
|---|---|
| `crates/nostr-remote-signer-core/` | Apache-2.0 |
| `crates/nostr-remote-signer/` (daemon) | AGPL-3.0-or-later |

The core is Apache-2.0 so it can be integrated anywhere, including in
Apache-2.0 projects. The daemon is AGPL-3.0: running a modified version as a
network service requires publishing your modifications. A commercial licence
removing that obligation is available — open an issue.

## Contributing

Contributions require a `Signed-off-by` line (`git commit -s`), certifying the
[DCO](DCO).

## Security

Nostr signs with Schnorr BIP-340. No commodity KMS or HSM can produce a Nostr
signature, so the Schnorr computation always happens in this process. The claim
this project makes is **"the key never resides on an agent host"** — not "the key
never leaves a HSM".