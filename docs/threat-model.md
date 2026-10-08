# Threat model

What `nostr-remote-signer` protects, against whom, and what it does not protect.

## What is protected

| Asset | Where it lives |
|---|---|
| Custodied secret keys: the identities agents sign as | Sealed on the vault's disk; in clear only in `bunkerd`'s memory |
| Transport keys, one per `bunker://` URI | Same |
| Root of trust: the passphrase | `bunkerd`'s environment, for the life of the process |
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

This is the gap an attested enclave closes (see below).

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

## What an enclave would add

Today, root on the vault host has the keys.

The plan is to run `bunkerd` in an AWS Nitro Enclave: no persistent storage, no shell,
no network except a vsock to its parent instance. KMS would release the data key only
to an enclave whose image measurement is pinned in the key policy
(`kms:RecipientAttestation:ImageSha384`). Root on the parent instance could then deny
service and observe metadata, but could no longer decrypt the key.

What would still be true:

- the key is used in clear inside the enclave, so a bug in the enclave image is a bug
  in the trusted base;
- whoever can change the KMS key policy decides which image gets the key;
- the claim stays **"the key never resides on an agent host"**, and becomes **"and
  only a publicly measurable image can decrypt it"**. It never becomes "the key never
  leaves a HSM".
