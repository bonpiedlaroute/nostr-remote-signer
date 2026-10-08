# nostr-remote-signer

A NIP-46 remote signer for Nostr agents. The agent host holds no secret key, only a
revocable credential. The vault holds the keys, applies a default-deny policy, journals
every decision, and cuts an agent off on its next request when you revoke it.

Works with any NIP-46 client. Demonstrated against a self-hosted Buzz relay.

> **Status: pre-release, unaudited.** Do not trust it with a key you cannot afford to lose.

## How it works

```
  agent host                   bunker-relay                  bunkerd (the vault)
  no secret key                own process, no keys          sealed keys, policy, journal
 ┌────────────────┐  kind     ┌───────────────────────┐     ┌─────────────────────────────┐
 │ agent          │  24133    │ NIP-46 only           │     │ decrypt                     │
 │  token         │──NIP-44──►│ addressed to bunker   │────►│ → credential → rate → policy│
 │  transport key │           │ per-IP + global rate  │     │ → sign (Schnorr, in memory) │
 │                │◄──────────│                       │◄────│ → one journal line          │
 └───────┬────────┘  signed   └───────────────────────┘     └─────────────────────────────┘
         │           event
         │ publishes the signed event
         ▼
   any Nostr relay
```

1. The agent sends encrypted NIP-46 requests to the bunker's transport relay.
2. `bunker-relay` admits only NIP-46 traffic addressed to this bunker, at a bounded rate.
3. `bunkerd` checks the agent's credential, the rate limits and the policy, signs with the
   custodied key, and writes one journal line. It never writes the content.
4. The agent publishes the signed event wherever it wants.

## What it does

| | |
|---|---|
| **Key custody** | Keys are sealed at rest by envelope encryption: a random data key (XChaCha20-Poly1305) wrapped by a root of trust, unwrapped once per key at boot. `bunkerd` uses a passphrase (`age`, scrypt). An AWS KMS backend (`GenerateDataKey`) exists in the library behind `--features aws`; `bunkerd` cannot select it yet. |
| **Memory hygiene** | Core dumps disabled, all memory locked against swap (`mlockall`, Linux only: macOS does not implement it), secrets zeroized on drop, `Debug` output redacted. A test runs the binary and searches its whole output for the key. |
| **Policy** | Default-deny allowlist of NIP-46 methods and event kinds (`policy.json`). |
| **Rate limits** | Token buckets per caller and for the whole bunker, checked before anything else. |
| **Agents** | Each agent has a random token; the vault stores only its SHA-256. One agent acts for one identity. |
| **Revocation** | Remove the agent from `agents.json`, send `SIGHUP`: its next request is refused, open session included. An invalid file revokes every agent instead of keeping a stale list. |
| **Audit journal** | One JSON line per decision: time, identity, caller, agent, method, kind, decision, reason. No content, ever. Append-only, mode 0600, fsync per batch, off the signing path. Lines lost under saturation are counted and recorded. |
| **Several identities** | One process serves every identity in `identities.json`, one `bunker://` URI each. |
| **Transport** | `bunker-relay` is the bunker's own relay. It admits NIP-46 for this bunker only, with per-IP and global rate limits, which bounds how much a flood can make the vault decrypt. |

## Quickstart

Requires Rust 1.90+, `openssl` and `jq`. Three terminals.

**Terminal 1: keys and configuration**

```bash
git clone https://github.com/bonpiedlaroute/nostr-remote-signer
cd nostr-remote-signer

# The root of trust. Keep this passphrase safe: it is the only way to open the keys.
printf 'passphrase: '; read -rs BUNKER_PASSPHRASE; echo; export BUNKER_PASSPHRASE

# Two keys, generated and sealed locally, never displayed: the transport key (the one
# in the bunker:// URI) and the identity your agent will sign as. To custody an
# existing identity instead, run `seal` alone and paste its nsec.
openssl rand -hex 32 | cargo run -q --example seal -- signer.sealed.json
openssl rand -hex 32 | cargo run -q --example seal -- identity.sealed.json

cp identities.example.json identities.json
jq '.allowed_kinds += [1]' policy.example.json > policy.json   # also allow text notes
echo '{ "agents": [] }' > agents.json
```

`seal` prints the public key of each sealed key: first the transport key, then the
identity.

**Terminal 2: the relay, first**

```bash
cd nostr-remote-signer
BUNKER_RELAY_SIGNERS='<public key printed for signer.sealed.json>' \
    cargo run -q --bin bunker-relay
```

**Terminal 1: the vault**

```bash
cargo run -q --bin bunkerd
```

`bunkerd` prints the identity and its `bunker://` URI. Start the relay first: when it
is missing, `bunkerd` retries every 10 to 60 seconds, and requests sent in the
meantime are lost.

**Terminal 3: an agent**

```bash
cd nostr-remote-signer

# A token for the agent, readable by you only. Register its hash, then reload.
(umask 077; openssl rand -hex 32 | tr -d '\n' > my-agent.token)
jq -n --arg id '<npub printed by bunkerd>' \
      --arg h "$(openssl dgst -sha256 -r < my-agent.token | cut -d' ' -f1)" \
      '{agents: [{name: "my-agent", identity: $id, token_sha256: $h}]}' > agents.json
kill -HUP "$(pgrep -x bunkerd)"

# Sign remotely: this process never sees the identity's secret key.
URI='<bunker URI printed by bunkerd>'
cargo run -q --example sign -- "$URI&secret=$(cat my-agent.token)"

# Revoke, and the same command is refused.
echo '{ "agents": [] }' > agents.json && kill -HUP "$(pgrep -x bunkerd)"
cargo run -q --example sign -- "$URI&secret=$(cat my-agent.token)"   # Error: Rejected

jq -c . audit.log
```

## Configuration

`bunkerd` reads environment variables and three files. Every file is local to the
operator and ignored by git; the repository ships `*.example.json` templates.

| Variable | Default | |
|---|---|---|
| `BUNKER_PASSPHRASE` | — (required) | Root of trust for the sealed keys |
| `BUNKER_IDENTITIES` | `identities.json` | Sealed key pairs to serve, read at boot |
| `BUNKER_POLICY` | `policy.json` | Allowed methods, kinds and rate limits, read at boot |
| `BUNKER_AGENTS` | `agents.json` | Agents and their token hashes, reloaded on `SIGHUP` |
| `BUNKER_AUDIT_LOG` | `audit.log` | The journal |
| `BUNKER_RELAY` | `ws://127.0.0.1:7777` | Transport relay, written into the `bunker://` URIs |

`bunker-relay` reads `BUNKER_RELAY_SIGNERS` (required: the transport keys of the
`bunker://` URIs, comma-separated) and `BUNKER_RELAY_LISTEN` (default `127.0.0.1:7777`).

```jsonc
// identities.json — one entry per identity
[ { "signer": "signer.sealed.json", "user": "identity.sealed.json" } ]

// policy.json — default-deny: anything not listed is refused
{
  "allowed_methods": ["connect", "get_public_key", "sign_event", "ping"],
  "allowed_kinds": [9, 27235],
  "rate_limit": {
    "per_caller": { "burst": 20, "per_second": 2.0 },
    "global": { "burst": 100, "per_second": 10.0 }
  }
}

// agents.json — the token itself never reaches the vault
{ "agents": [ { "name": "my-agent", "identity": "npub1…", "token_sha256": "…" } ] }
```

Signals: `SIGHUP` reloads `agents.json`; `SIGINT` (Ctrl-C) stops after flushing the journal.

## The audit journal

```json
{"agent":"my-agent","at":1791323857,"caller":"8e81…","decision":"approved","identity":"c061…","kind":1,"method":"sign_event","reason":null}
{"agent":null,"at":1791323901,"caller":"3852…","decision":"denied","identity":"c061…","kind":null,"method":"connect","reason":"unauthorized"}
```

Reasons: `method_not_allowed`, `kind_not_allowed`, `rate_limited`, `unauthorized`,
`revoked`. `caller` is the agent's NIP-46 transport key; `agent` is the name its
credential proved, kept on refusals and after revocation.

## Threat model

In short:

- **A compromised agent host** can request signatures within the policy until it is
  revoked. It cannot obtain the key, and every request it makes is journaled.
- **A stolen copy of the vault's disk** yields sealed keys, which are useless without the
  root of trust.
- **Root on the vault host** gets the keys. Nostr signs with Schnorr (BIP-340), and no
  commodity KMS or HSM produces such signatures, so the key is in clear in the vault's
  memory while it signs. An attested enclave would close this gap (see Roadmap).
- **Anyone watching the relay** sees who talks to the bunker and when, never what they say.
- **A flood** cannot make the vault decrypt more than the relay's global rate. It can
  still deny service to legitimate agents while it lasts.

The full model, with known limitations, is in [docs/threat-model.md](docs/threat-model.md).

## Compared with Keycast

[Keycast](https://github.com/divinevideo/keycast) is the most complete open-source NIP-46
signer, and it is in production. The comparison below was checked against its source at
commit `953db4b` (2026-10-08). If anything here is outdated, please open an issue.

| | Keycast | nostr-remote-signer |
|---|---|---|
| Product | Multi-tenant service: web UI, OAuth, teams, HTTP RPC alongside NIP-46 | One daemon for one operator's agents, configured by files |
| Storage | PostgreSQL | Files |
| Keys at rest | AES-256-GCM; master key from a file, AWS KMS or GCP KMS | Envelope: one data key per key, wrapped by a passphrase (AWS KMS in the library only) |
| KMS calls | `Encrypt` / `Decrypt` on the payload | One unwrap per key, at boot |
| Policy | Reusable permission policies, managed in the UI | One default-deny file |
| Agent credentials | bcrypt-hashed connect secrets | SHA-256 of 256-bit random tokens |
| Per-signature audit | Removed in PR #39, citing privacy and performance | One line per decision, metadata only, off the signing path |
| Admin audit | Yes | No admin surface |
| Memory locking, core dumps | Not found in the code | `mlockall` (Linux), core dumps disabled |
| Transport | Any relay; its documentation uses public ones | Its own relay with a DoS guard, or any relay |
| Enclave attestation | No | Planned |

Keycast is the better choice for a hosted service with many users, a UI and team
management. This project targets a narrower case: agents that sign with a key
they must never hold, where every signature has to be accountable, and where the
next step is a key that even root on the vault host cannot read.

## Roadmap

- **Attested key release.** Run the vault in an AWS Nitro Enclave, with KMS releasing
  the data key only to an image whose measurement is pinned in the key policy
  (`kms:RecipientAttestation:ImageSha384`). Root on the host then cannot decrypt the key.
- KMS root of trust selectable in `bunkerd`.
- Hash-chained journal, for tamper evidence.
- Known agent transport keys at the relay, so that a flood cannot starve registered agents.

## Security

The claim this project makes is **"the key never resides on an agent host"**. It does
**not** claim "the key never leaves an HSM": no commodity KMS or HSM can produce a Nostr
signature, so the Schnorr computation always happens in the vault's process.

Please report vulnerabilities privately, through GitHub's private vulnerability reporting
on this repository.

## Licensing

This repository is dual-licensed by directory:

| Path | Licence |
|---|---|
| `crates/nostr-remote-signer-core/` | Apache-2.0 |
| `crates/nostr-remote-signer/` (daemon) | AGPL-3.0-or-later |

The core is Apache-2.0 so it can be integrated anywhere, including in Apache-2.0
projects. The daemon is AGPL-3.0: running a modified version as a network service
requires publishing your modifications. A commercial licence removing that obligation
is available — open an issue.

## Contributing

Contributions require a `Signed-off-by` line (`git commit -s`), certifying the
[DCO](DCO).
