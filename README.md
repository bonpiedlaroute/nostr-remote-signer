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
| **Key custody** | Keys are sealed at rest by envelope encryption: a random data key (XChaCha20-Poly1305) wrapped by a root of trust, unwrapped once per key at boot. `bunkerd` uses a passphrase (`age`, scrypt) by default, or AWS KMS when built with `--features aws`. In an AWS Nitro Enclave, KMS releases the data keys to the measured image only ([proof](#proof-attested-key-release)). |
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
| `BUNKER_ROOT_OF_TRUST` | `passphrase` | `passphrase`; with `--features aws`, `aws-kms`, or `nitro` (KMS, attested from an enclave) |
| `BUNKER_PASSPHRASE` | — (required with `passphrase`) | Root of trust for the sealed keys |
| `BUNKER_KMS_KEY_ID` | — (required with `aws-kms`, `nitro`) | The KMS key that wraps the data keys |
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
  memory while it signs. In an AWS Nitro Enclave, that memory is out of the host's reach
  and KMS releases the key to the measured image only: root on the parent instance can no
  longer decrypt it ([proof](#proof-attested-key-release)).
- **Anyone watching the relay** sees who talks to the bunker and when, never what they say.
- **A flood** cannot make the vault decrypt more than the relay's global rate. It can
  still deny service to legitimate agents while it lasts.

The full model, with known limitations, is in [docs/threat-model.md](docs/threat-model.md).

## Proof: attested key release

The vault can run in an AWS Nitro Enclave. Its keys are then sealed with a KMS key whose
policy lets only that enclave decrypt them: KMS checks the enclave's attestation document,
signed by AWS, against the image measurement pinned in the policy (PCR0), and answers in a
form only the enclave can open.

On 2026-10-15, on an EC2 instance, with a dev identity:

| Who asks KMS to decrypt the sealed key | Result |
|---|---|
| Root on the parent instance, with the instance's role | Refused |
| The vault's image, started in debug mode, where its PCRs read as zeros | Refused |
| The same image, without debug | Opens its keys; an agent gets an event signed |
| An administrator of the AWS account | Refused |

```text
[root@ip-172-31-17-228 ~]# aws sts get-caller-identity --query Arn --output text
arn:aws:sts::111122223333:assumed-role/bunker-vault-dev/i-0d2a500d68275b9d5
[root@ip-172-31-17-228 ~]# aws kms decrypt --region eu-west-3 --ciphertext-blob fileb:///tmp/wrapped-dek
aws: [ERROR]: An error occurred (AccessDeniedException) when calling the Decrypt operation: User: arn:aws:sts::111122223333:assumed-role/bunker-vault-dev/i-0d2a500d68275b9d5 is not authorized to perform: kms:Decrypt on resource: arn:aws:kms:eu-west-3:111122223333:key/4eb984c8-6e72-42ec-ad5d-9659f98f8c9f because no resource-based policy allows the kms:Decrypt action

[ec2-user@ip-172-31-17-228 ~]$ nitro-cli run-enclave --eif-path vault-d2-5.eif --cpu-count 2 --memory 2048 \
    --debug-mode --attach-console
…
Error: key unwrapper backend: service error: unhandled error (AccessDeniedException): …

[ec2-user@ip-172-31-17-228 ~]$ nitro-cli run-enclave --eif-path vault-d2-5.eif --cpu-count 2 --memory 2048
…
[ec2-user@ip-172-31-17-228 ~]$ ./sign "$URI&secret=$(cat dev-agent.token)"
…
✅ event signed remotely
…
[ec2-user@ip-172-31-17-228 ~]$ tail -1 audit.log
{"agent":"dev-agent",…,"decision":"approved",…,"kind":1,"method":"sign_event","reason":null}
```

The same PCR0 appears in the key policy in force, in `nitro-cli`'s measurement of the image,
and in the attested `Decrypt` that CloudTrail recorded. The full transcript, the policy, the
measurements and the CloudTrail events are in [docs/proof/2026-10-15](docs/proof/2026-10-15/),
with the account ID masked. The scripts in [`enclave/aws/`](enclave/aws/) created the key, its
policy and the instance.

What this does not show:

- **The build is not reproducible yet.** You can check that the policy, the image and
  CloudTrail agree on one PCR0, not recompute that PCR0 from these sources.
- **The AWS account's administrators can rewrite the key policy.** CloudTrail records every
  change.

## Compared with Keycast

[Keycast](https://github.com/divinevideo/keycast) is the most complete open-source NIP-46
signer, and it is in production. The comparison below was checked against its source at
commit `953db4b` (2026-10-08). If anything here is outdated, please open an issue.

| | Keycast | nostr-remote-signer |
|---|---|---|
| Product | Multi-tenant service: web UI, OAuth, teams, HTTP RPC alongside NIP-46 | One daemon for one operator's agents, configured by files |
| Storage | PostgreSQL | Files |
| Keys at rest | AES-256-GCM; master key from a file, AWS KMS or GCP KMS | Envelope: one data key per key, wrapped by a passphrase or AWS KMS |
| KMS calls | `Encrypt` / `Decrypt` on the payload | One unwrap per key, at boot |
| Policy | Reusable permission policies, managed in the UI | One default-deny file |
| Agent credentials | bcrypt-hashed connect secrets | SHA-256 of 256-bit random tokens |
| Per-signature audit | Removed in PR #39, citing privacy and performance | One line per decision, metadata only, off the signing path |
| Admin audit | Yes | No admin surface |
| Memory locking, core dumps | Not found in the code | `mlockall` (Linux), core dumps disabled |
| Transport | Any relay; its documentation uses public ones | Its own relay with a DoS guard, or any relay |
| Enclave attestation | No | AWS Nitro Enclaves: KMS releases the data keys to the measured image only ([proof](#proof-attested-key-release)) |

Keycast is the better choice for a hosted service with many users, a UI and team
management. This project targets a narrower case: agents that sign with a key
they must never hold, where every signature has to be accountable, and where, in an
enclave, even root on the host cannot decrypt the key.

## Roadmap

- **A reproducible enclave build**, so that anyone can recompute the image's PCR0 from the
  sources.
- A guide to run the vault in an enclave, under QEMU and on EC2, and to reproduce the proof.
- Hash-chained journal, for tamper evidence.
- Known agent transport keys at the relay, so that a flood cannot starve registered agents.

## Security

The claim this project makes is **"the key never resides on an agent host"**. It does
**not** claim "the key never leaves an HSM": no commodity KMS or HSM can produce a Nostr
signature, so the Schnorr computation always happens in the vault's process. In an AWS
Nitro Enclave, it adds that only the image whose measurement the KMS key policy pins can
decrypt the key, and that root on the host cannot.

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
