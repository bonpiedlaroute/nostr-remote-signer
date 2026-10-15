# Threat model

What `nostr-remote-signer` protects, against whom, and what it does not protect.

## What is protected

| Asset | Where it lives |
|---|---|
| Custodied secret keys: the identities agents sign as | Sealed on the vault's disk; in clear only in `bunkerd`'s memory |
| Transport keys, one per `bunker://` URI | Same |
| Root of trust: a passphrase, or a KMS key | The passphrase: `bunkerd`'s environment, for the life of the process. A KMS key: in AWS KMS; in an enclave, its policy releases the data keys to the measured image only |
| Agent tokens | On each agent host. The vault stores only their SHA-256 |
| The journal | `audit.log` on the vault host |

## Trust boundaries

```
  agent host          │  transport relay           │  vault host
  token,              │  sees encrypted NIP-46     │  sealed keys on disk,
  transport key       │  traffic and its metadata  │  keys in clear in memory,
  no secret key       │                            │  policy, agents, journal
```

Requests are NIP-44 encrypted between the agent's transport key and the bunker's
transport key: the relay carries them but cannot read them.

## Adversaries

### 1. A compromised agent host

**Gets** the agent's token and its transport key.

**Can** request signatures within the policy (methods, event kinds), within the rate
limits, for the one identity the agent is bound to, until it is revoked.

**Cannot** obtain the secret key, which never reaches the agent host, nor act for
another identity.

**Leaves** one journal line per request, naming the agent.

**Response:** remove the agent from `agents.json`, send `SIGHUP`. The next request is
refused, including on a session already open.

**Residual risk:** events signed before revocation stay valid. Nostr has no way to
recall a signature.

### 2. Anyone who knows the bunker's public key

The bunker's transport key is public: it is tagged in every kind 24133 event on the relay.

**Can send requests.** Without a valid token, every request is refused as
`unauthorized`, `connect` included.

**Can flood.** `bunker-relay` admits a bounded rate of events addressed to the bunker,
per source IP and globally, and the vault decrypts at most that many. The vault's CPU
is protected.

**Cannot be prevented from denying service.** The flood uses up the same rate budget as
legitimate agents, so they are refused while it lasts. Availability under flood is
**not** protected.

### 3. The relay operator, or anyone reading the relay

**Sees** which transport keys talk to the bunker, when, how often, and how large the
messages are.

**Does not see** requests, signed events or tokens: they are encrypted end to end.

With `bunker-relay`, anyone who can connect can subscribe to kind 24133. It listens on
`127.0.0.1` by default; exposing it exposes this metadata.

### 4. Someone who copies the vault's disk

A backup, a snapshot or a stolen volume.

**Gets** the sealed keys, the agent list with token hashes, the policy and the journal.

**Cannot** open the sealed keys without the root of trust. A token hash does not lead
back to its token: tokens are 256 random bits.

**Can read** the journal, which holds the metadata of every request: who, when, which
kind. Not the content.

**The passphrase is the weak point.** `age`'s scrypt slows down offline guessing; it does
not make a weak passphrase strong.

### 5. Root, or the `bunkerd` user, on the vault host at runtime

**Gets everything.** The secret keys are in clear in the process's memory: Schnorr
signing (BIP-340) has to happen there, since no commodity KMS or HSM can produce a
Nostr signature. The passphrase is in the process's environment, readable through
`/proc/<pid>/environ`.

Memory locking and disabled core dumps reduce **accidental** leaks to swap and crash
dumps. They do nothing against a deliberate attacker with root.

This is the gap the enclave closes for root on the parent instance (see below).

### 6. Someone with write access to the journal

**Can** rewrite or truncate it. `O_APPEND` stops the vault from overwriting its own
history, not another process. The journal is **not** tamper-evident: there is no hash
chain. If the journal has to serve as evidence, ship it off the host as it is written.

## Assumptions

- The operating system, the Rust toolchain and the dependencies are correct: `nostr`,
  `nostr-connect`, `nostr-sdk`, `secp256k1`, `age`, `chacha20poly1305`.
- Agent tokens come from a CSPRNG and are readable by the agent only.
- The vault host's clock is roughly right, since journal timestamps depend on it.

## Known limitations

- **macOS:** no memory locking; the kernel does not implement `mlockall`.
- **Debug logs:** with `nostr_connect=debug`, every decrypted NIP-46 message is logged,
  tokens and event content included. Never enable it in production; the default filter
  is safe.
- **Shutdown:** `SIGTERM` is not handled. Stop with `SIGINT` (Ctrl-C) so that the
  journal's last batch is flushed.
- **Rate per caller** is keyed by transport key, not by agent. An agent that reconnects
  with a new transport key each time is bounded by the global limit only.
- **One live transport key per agent and identity:** two processes sharing one token
  disconnect each other. Use one token per process.
- **The examples pass the token in `argv`,** where `ps` shows it.
- **Relay restarts:** `bunkerd` reconnects within 10 to 60 seconds. Requests sent in
  the meantime are lost, and the agent times out.
- **`bunker-relay` speaks plain `ws://`.** Agents on other hosts need a TLS reverse proxy
  in front of it.
- **The relay's limits are constants.** Keep its global rate in line with the vault's
  global rate in `policy.json`.

## What the enclave adds

`bunkerd` can run in an AWS Nitro Enclave: no persistent storage, no shell, no network
except a vsock to its parent instance. The data keys are wrapped by a KMS key whose policy
lets only the enclave decrypt them: KMS checks the enclave's attestation document, signed
by AWS, against the image measurement pinned in the policy
(`kms:RecipientAttestation:ImageSha384`, PCR0), and answers in a form only the enclave can
open. Root on the parent instance can deny service and observe metadata, but cannot
decrypt the keys.

Shown on EC2 on 2026-10-15 ([proof](proof/2026-10-15/)):

| Who asks KMS to decrypt a sealed key | Result |
|---|---|
| Root on the parent instance, with the instance's role | Refused |
| The same image in debug mode, where its PCRs read as zeros | Refused |
| The image whose PCR0 the policy pins | Decrypts, inside the enclave |
| An administrator of the AWS account, under that policy | Refused |

What is still true:

- the key is used in clear inside the enclave, so a bug in the enclave image is a bug
  in the trusted base;
- the trusted base now includes AWS: the Nitro hypervisor, which signs the attestation
  documents, and KMS;
- whoever can change the KMS key policy decides which image gets the key: the AWS
  account's administrators. CloudTrail records every change;
- the enclave build is not reproducible yet: a reader can check that the policy, the
  image and CloudTrail agree on one PCR0, not recompute it from the sources;
- the parent instance hands the enclave its AWS credentials at boot and relays its
  traffic. It can withhold them, which denies service, but cannot read what they
  protect;
- the claim stays **"the key never resides on an agent host"**, and becomes **"and only
  the image whose measurement the key policy pins can decrypt it"**. It never becomes "the
  key never leaves an HSM".
