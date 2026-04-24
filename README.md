<p align="center">
  <img src="https://img.shields.io/badge/Go-1.24-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go 1.24" />
  <img src="https://img.shields.io/badge/Redis-Required-DC382D?style=for-the-badge&logo=redis&logoColor=white" alt="Redis" />
  <img src="https://img.shields.io/badge/Encryption-AES--GCM-blueviolet?style=for-the-badge&logo=letsencrypt&logoColor=white" alt="AES-GCM" />
  <img src="https://img.shields.io/badge/Key%20Exchange-X25519-orange?style=for-the-badge" alt="X25519" />
</p>

# 🔐 MetaChat

**End-to-end encrypted messaging demo built in Go**, featuring X25519 Diffie-Hellman key exchange, Double Ratchet–inspired key derivation, and AES-256-GCM authenticated encryption — all relayed through a zero-knowledge HTTP server backed by Redis.

> The server **never** sees plaintext messages. It only stores opaque ciphertext blobs and public keys.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Cryptographic Design](#cryptographic-design)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Getting Started](#getting-started)
- [Usage](#usage)
- [How It Works](#how-it-works)
- [API Reference](#api-reference)
- [Security Considerations](#security-considerations)
- [License](#license)

---

## Overview

MetaChat is a minimal, educational implementation of end-to-end encrypted messaging between two parties (**Matteo** and **Benny**) using modern cryptographic primitives. The project demonstrates how protocols like the Signal Protocol work at a fundamental level, without any third-party crypto frameworks — just the Go standard library and `golang.org/x/crypto`.

### Key Features

| Feature | Description |
|---|---|
| **X25519 Key Exchange** | Elliptic-curve Diffie-Hellman for shared secret derivation |
| **HKDF-SHA256** | Deterministic key derivation from shared secrets |
| **AES-256-GCM** | Authenticated encryption with associated data |
| **Key Ratcheting** | Forward secrecy via Double Ratchet–inspired chain key advancement |
| **Zero-Knowledge Relay** | Server cannot decrypt messages — it only forwards ciphertext |
| **Redis Mailbox** | Asynchronous message delivery via Redis lists |

---

## Architecture

```
┌──────────┐          ┌──────────────────┐          ┌──────────┐
│          │  HTTPS   │                  │  HTTPS   │          │
│  Matteo  │ -------> │   Relay Server   │ <------- │  Benny   │
│ (sender) │          │  (HTTP + Redis)  │          │(receiver)│
│          │          │                  │          │          │
└──────────┘          └──────────────────┘          └──────────┘
     │                        │                          │
     │  1. Fetch Benny's      │  Stores prekeys &        │  1. Upload public key
     │     public key         │  encrypted messages      │     (prekey bundle)
     │                        │  in Redis                │
     │  2. DH key exchange    │                          │  2. Poll mailbox
     │     (X25519)           │                          │     for messages
     │                        │                          │
     │  3. Ratchet + derive   │                          │  3. DH key exchange
     │     message key        │                          │     (X25519)
     │                        │                          │
     │  4. Encrypt (AES-GCM)  │                          │  4. Ratchet + derive
     │     & send ciphertext  │                          │     message key
     │                        │                          │
     │                        │                          │  5. Decrypt (AES-GCM)
     └────────────────────────┘──────────────────────────┘
```

---

## Cryptographic Design

```
Matteo                                        Benny
  │                                             │
  │          ┌─ Benny's X25519 public key ──┐   │
  │          │  (fetched from server)       │   │
  │          └──────────────────────────────┘   │
  │                                             │
  ├─ Generate ephemeral X25519 keypair          ├─ Generate identity X25519 keypair
  │                                             │
  ├─ shared_secret = X25519(matteo_priv,        ├─ shared_secret = X25519(benny_priv,
  │                         benny_pub)          │                        matteo_ephemeral)
  │                                             │
  ├─ root_key  = HKDF(shared_secret, "root")   ├─ root_key  = HKDF(shared_secret, "root")
  ├─ chain_key = HKDF(root_key, "chain")        ├─ chain_key = HKDF(root_key, "chain")
  ├─ chain_key = HKDF(chain_key, "chain-step") ├─ chain_key = HKDF(chain_key, "chain-step")
  ├─ msg_key   = HKDF(chain_key, "msg")        ├─ msg_key   = HKDF(chain_key, "msg")
  │                                             │
  ├─ ciphertext = AES-GCM(msg_key, plaintext)  ├─ plaintext = AES-GCM(msg_key, ciphertext)
  │                                             │
  └─── ciphertext + nonce + ephemeral_pub ──────┘
                  (via server)
```

---

## Project Structure

```
metachat/
├── go.mod                     # Module definition & dependencies
├── server/
│   └── main.go                # HTTP relay server (Redis-backed)
├── matteo/
│   └── main.go                # Sender client — encrypts & sends messages
├── benny/
│   └── main.go                # Receiver client — polls, decrypts & displays
└── internal/
    ├── crypto/
    │   └── crypto.go          # X25519 keygen, DH, HKDF-SHA256, AES-GCM
    └── ratchet/
        └── ratchet.go         # Double Ratchet key derivation chain
```

| Package | Responsibility |
|---|---|
| `server/` | HTTP endpoints for prekey upload/fetch and encrypted message relay. All data stored in Redis. |
| `matteo/` | Fetches Benny's public key, performs DH, derives keys via ratchet, encrypts with AES-GCM, sends ciphertext. |
| `benny/` | Generates identity keypair, uploads public key, polls for messages, derives keys, decrypts. |
| `internal/crypto` | Low-level crypto: X25519 key generation & DH, HKDF-SHA256 extraction, AES-256-GCM seal/open. |
| `internal/ratchet` | Manages root key, chain key, and message key derivation with ratchet stepping for forward secrecy. |

---

## Prerequisites

- **Go** 1.24+  
- **Redis** server running on `localhost:6379`

### Install Redis

<details>
<summary><strong>Windows</strong></summary>

```powershell
# Using Chocolatey
choco install redis-64

# Or use WSL
wsl --install
sudo apt update && sudo apt install redis-server
sudo service redis-server start
```

</details>

<details>
<summary><strong>macOS</strong></summary>

```bash
brew install redis
brew services start redis
```

</details>

<details>
<summary><strong>Linux</strong></summary>

```bash
sudo apt update && sudo apt install redis-server
sudo systemctl start redis
```

</details>

---

## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/your-username/metachat.git
cd metachat
```

### 2. Install Go dependencies

```bash
go mod tidy
```

### 3. Verify Redis is running

```bash
redis-cli ping
# Expected output: PONG
```

---

## Usage

Open **three separate terminals** and run the components in order:

### Terminal 1 — Start the relay server

```bash
go run ./server
```
```
[SERVER] Running on :8080 (Redis: localhost:6379)
```

### Terminal 2 — Start Benny (receiver)

```bash
go run ./benny
```
```
[BENNY] Generating Benny X25519 identity keypair...
[BENNY] Uploading Benny public key to server (stored in Redis as prekey:benny)...
[BENNY] Benny ready. Polling mailbox from server (secure_mailbox:benny in Redis)...
```

### Terminal 3 — Send a message as Matteo

```bash
# Interactive mode
go run ./matteo

# Or pass the message directly
go run ./matteo Hello Benny, this is a secret message!
```
```
[MATTEO] Fetching Benny prekey from server...
[MATTEO] Benny prekey received.
[MATTEO] Generating Matteo ephemeral X25519 keypair...
[MATTEO] Computing shared secret (X25519 DH)...
[MATTEO] Initializing ratchet and deriving message key...
[MATTEO] Encrypting message with AES-GCM...
[MATTEO] Sending encrypted message to server (queued for benny in Redis)...
[MATTEO] Done. Message sent.
```

### Benny receives the message

```
[BENNY] Received encrypted message. Deriving shared secret (X25519 DH)...
[BENNY] Initializing ratchet and deriving message key...
[BENNY] Decrypting with AES-GCM...
[BENNY] Benny received: Hello Benny, this is a secret message!
```

---

## How It Works

### Step-by-step flow

1. **Benny** generates an X25519 identity keypair and uploads his public key to the server as a *prekey bundle*.

2. **Matteo** fetches Benny's prekey bundle from the server and generates an *ephemeral* X25519 keypair.

3. **Matteo** computes a shared secret via X25519 Diffie-Hellman: `shared = X25519(matteo_priv, benny_pub)`.

4. The shared secret is fed into a **ratchet**:
   - `root_key = HKDF-SHA256(shared_secret, "root")`
   - `chain_key = HKDF-SHA256(root_key, "chain")`
   - `chain_key = HKDF-SHA256(chain_key, "chain-step")` *(advance the chain)*
   - `msg_key = HKDF-SHA256(chain_key, "msg")`

5. **Matteo** encrypts his plaintext with **AES-256-GCM** using the derived `msg_key`, producing a `nonce` and `ciphertext`.

6. Matteo sends `{ephemeral_pub, nonce, ciphertext}` to the server, which queues it in Benny's Redis mailbox.

7. **Benny** polls his mailbox, retrieves the message, and performs the **same key derivation** using `X25519(benny_priv, matteo_ephemeral_pub)` to derive the identical `msg_key`.

8. **Benny** decrypts the ciphertext with AES-256-GCM and reads the plaintext.

---

## API Reference

The relay server exposes four HTTP endpoints:

| Method | Endpoint | Query Params | Body | Description |
|--------|----------|-------------|------|-------------|
| `POST` | `/upload_prekey` | `user` | `{"identity_key": [bytes]}` | Upload a user's public key bundle |
| `GET` | `/prekey` | `user` | — | Fetch a user's prekey bundle |
| `POST` | `/send_secure` | `to` | `{"from_identity", "ephemeral_key", "nonce", "ciphertext"}` | Queue an encrypted message for a recipient |
| `GET` | `/fetch_secure` | `user` | — | Pop the next encrypted message from a user's mailbox |

### Redis Keys

| Key Pattern | Type | Description |
|---|---|---|
| `prekey:<user>` | String | JSON-encoded prekey bundle for `<user>` |
| `secure_mailbox:<user>` | List | Queue of encrypted messages awaiting delivery |

---

## Security Considerations

> ⚠️ **This is an educational project** — not intended for production use.

| Aspect | Status | Notes |
|---|---|---|
| Forward secrecy | ✅ Partial | Chain key ratcheting provides per-message keys; full Double Ratchet with DH ratchet steps is partially implemented |
| Authenticated encryption | ✅ | AES-256-GCM provides confidentiality + integrity |
| Key exchange | ✅ | X25519 ECDH — industry standard |
| Identity verification | ❌ | No certificate pinning or trust-on-first-use mechanism |
| Replay protection | ❌ | No message counters or sequence validation |
| Transport security | ❌ | HTTP (not TLS) between clients and server |
| Key persistence | ❌ | Keys are ephemeral — regenerated each run |
| Multi-message sessions | ❌ | Benny exits after receiving one message |

### For production use, you would additionally need:
- TLS for all client ↔ server communication
- Identity verification (e.g., safety numbers, QR codes)
- Message ordering and replay protection
- Persistent key storage with secure key management
- Full Double Ratchet with header encryption
- Multi-device support

---

## License

This project is provided as-is for educational purposes.
