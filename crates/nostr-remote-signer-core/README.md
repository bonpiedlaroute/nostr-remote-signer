# nostr-remote-signer-core

The Apache-2.0 core of [nostr-remote-signer](https://github.com/bonpiedlaroute/nostr-remote-signer),
a NIP-46 remote signer with key custody, policy and audit.

- `KeyUnwrapper` is the root-of-trust boundary: a backend wraps and unwraps a 32-byte data key,
  nothing else. The envelope that protects the secret lives once, in the daemon.
- `AuditRecord` and `AuditSink` describe one record per signing decision: who asked, which
  method, which kind, the decision. Never the content.

These traits are Apache-2.0 so that other projects can adopt them. The daemon is
AGPL-3.0-or-later.
