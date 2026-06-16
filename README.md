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
- [Interface and Storage](#interface-and-storage)
- [How It Works](#how-it-works)
- [API Reference](#api-reference)
- [Security Considerations](#security-considerations)
- [License](#license)

---

## Overview

MetaChat is a minimal, educational implementation of end-to-end encrypted messaging between many named clients, such as `john`, `smite`, `matteo`, `benny`, or any other username you create. The project demonstrates how protocols like the Signal Protocol work at a fundamental level, without any third-party crypto frameworks — just the Go standard library and `golang.org/x/crypto`.

### Key Features

| Feature | Description |
|---|---|
| **X25519 Key Exchange** | Elliptic-curve Diffie-Hellman for shared secret derivation |
| **HKDF-SHA256** | Deterministic key derivation from shared secrets |
| **AES-256-GCM** | Authenticated encryption with associated data |
| **Key Ratcheting** | Forward secrecy via Double Ratchet–inspired chain key advancement |
| **Zero-Knowledge Relay** | Server cannot decrypt messages — it only forwards ciphertext |
| **Redis Mailbox** | Asynchronous message delivery via Redis lists |
| **Multi-Client CLI** | Run one reusable client as any username and connect to 10-20+ peers |

---

## Architecture

```
┌──────────┐          ┌──────────────────┐          ┌──────────┐
│          │   HTTP   │                  │   HTTP   │          │
│  john    │ -------> │   Relay Server   │ <------- │  smite   │
│ client   │          │  (HTTP + Redis)  │          │ client   │
│          │          │                  │          │          │
└──────────┘          └──────────────────┘          └──────────┘
     │                        │                          │
     │  1. Fetch peer's       │  Stores users, contacts, │  1. Upload public key
     │     public key         │  prekeys, and ciphertext │     (prekey bundle)
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
Sender                                        Receiver
  │                                             │
  │          ┌─ receiver X25519 public key ─┐   │
  │          │  (fetched from server)       │   │
  │          └──────────────────────────────┘   │
  │                                             │
  ├─ Generate ephemeral X25519 keypair          ├─ Generate identity X25519 keypair
  │                                             │
  ├─ shared_secret = X25519(ephemeral_priv,     ├─ shared_secret = X25519(receiver_priv,
  │                         receiver_pub)       │                        sender_ephemeral)
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
├── client/
│   └── main.go                # Generic multi-user client
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
| `server/` | HTTP endpoints for users, contacts, prekey upload/fetch, and encrypted message relay. All data stored in Redis. |
| `client/` | Reusable interactive CLI for any username; supports user discovery, connections, sending, and mailbox polling. |
| `matteo/` | Legacy sender demo that fetches Benny's public key and sends one encrypted message. |
| `benny/` | Legacy receiver demo that uploads Benny's key and decrypts one message. |
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

Open one terminal for the server and one terminal per client.

### Terminal 1 — Start the relay server

```bash
go run ./server
```
```
[SERVER] Running on :8080 (Redis: 127.0.0.1:6379)
```

Optional configuration:

```bash
REDIS_ADDR=127.0.0.1:6379 HTTP_ADDR=:8080 go run ./server
```

### Terminal 2 — Start John

```bash
go run ./client -user john
```
```
[john] Registered prekey with http://localhost:8080
[john] Interactive MetaChat ready. Use /help for commands.
```

### Terminal 3 — Start Smite

```bash
go run ./client -user smite
```
```
[smite] Registered prekey with http://localhost:8080
[smite] Interactive MetaChat ready. Use /help for commands.
```

### Create a connection and chat

In John's terminal:

```text
/users
/connect smite
/to smite
hello smite, this is encrypted
```

Smite receives:

```text
[john -> smite] hello smite, this is encrypted
```

You can start more clients the same way:

```bash
go run ./client -user alice
go run ./client -user bob
go run ./client -user charlie
```

The server accepts usernames with letters, numbers, dots, underscores, and hyphens, so running 10-20 local clients is just a matter of opening more terminals or starting them with different `-user` values.

### One-shot sends

You can also send one message without entering the interactive shell:

```bash
go run ./client -user john -to smite -message "quick encrypted note"
go run ./client -user john -to smite "same idea using CLI args"
```

Keep a client listening without the shell:

```bash
go run ./client -user smite -listen
```

### Interactive commands

| Command | Description |
|---|---|
| `/users` | List registered users with uploaded prekeys |
| `/contacts` | List this user's saved connections |
| `/connect <user>` | Save a bidirectional connection |
| `/to <user>` | Set the active recipient for plain text input |
| `/send <user> <message>` | Send one encrypted message |
| `/quit` | Exit the client |

### Legacy two-user demo

The original demo still works:

```bash
go run ./benny
go run ./matteo "Hello Benny, this is a secret message!"
```

---

## Interface and Storage

The terminal client is enough for the next project step because it gives you a real interface for creating users, seeing users, connecting contacts, and sending messages without adding frontend complexity yet.

Redis is enough for this demo and for 10-20 local clients because it is doing the right relay jobs: public prekey lookup, contact sets, and encrypted mailbox queues. For a bigger app, keep Redis for fast queues and online/session state, then add a durable database such as SQLite or Postgres for accounts, profiles, long-lived contacts, device records, audit metadata, and message-delivery state.

---

## How It Works

### Step-by-step flow

1. Each client generates an X25519 identity keypair and uploads its public key to the server as a *prekey bundle*.

2. The sender fetches the receiver's prekey bundle from the server and generates an *ephemeral* X25519 keypair.

3. The sender computes a shared secret via X25519 Diffie-Hellman: `shared = X25519(sender_ephemeral_priv, receiver_pub)`.

4. The shared secret is fed into a **ratchet**:
   - `root_key = HKDF-SHA256(shared_secret, "root")`
   - `chain_key = HKDF-SHA256(root_key, "chain")`
   - `chain_key = HKDF-SHA256(chain_key, "chain-step")` *(advance the chain)*
   - `msg_key = HKDF-SHA256(chain_key, "msg")`

5. The sender encrypts the plaintext with **AES-256-GCM** using the derived `msg_key`, producing a `nonce` and `ciphertext`.

6. The sender sends `{from_user, from_identity, ephemeral_pub, nonce, ciphertext}` to the server, which queues it in the receiver's Redis mailbox.

7. The receiver polls its mailbox, retrieves the message, and performs the **same key derivation** using `X25519(receiver_priv, sender_ephemeral_pub)` to derive the identical `msg_key`.

8. The receiver decrypts the ciphertext with AES-256-GCM and reads the plaintext.

---

## API Reference

The relay server exposes these HTTP endpoints:

| Method | Endpoint | Query Params | Body | Description |
|--------|----------|-------------|------|-------------|
| `POST` | `/upload_prekey` | `user` | `{"identity_key": [bytes]}` | Upload a user's public key bundle |
| `GET` | `/prekey` | `user` | — | Fetch a user's prekey bundle |
| `GET` | `/users` | — | — | List users that have uploaded prekeys |
| `POST` | `/connect` | `user`, `peer` | — | Save a bidirectional contact connection |
| `GET` | `/contacts` | `user` | — | List a user's saved contacts |
| `POST` | `/send_secure` | `to` | `{"from_user", "from_identity", "ephemeral_key", "nonce", "ciphertext"}` | Queue an encrypted message for a recipient |
| `GET` | `/fetch_secure` | `user` | — | Pop the next encrypted message from a user's mailbox |

### Redis Keys

| Key Pattern | Type | Description |
|---|---|---|
| `users` | Set | Registered usernames with uploaded prekeys |
| `prekey:<user>` | String | JSON-encoded prekey bundle for `<user>` |
| `contacts:<user>` | Set | Saved contact names for `<user>` |
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
| Multi-message sessions | ✅ Demo | Generic clients can keep polling and sending; legacy Benny still exits after one message |

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
