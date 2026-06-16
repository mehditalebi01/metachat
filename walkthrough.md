# 🔐 MetaChat — Complete Project Walkthrough

> **Project**: MetaChat — End-to-End Encrypted Messaging  
> **Authors**: Mehdi Talebikhatir (558948) & Benyamin Baharizadeh (560587)  
> **University**: University of Messina — Department of Engineering  
> **Course**: Web Programming & System Security  
> **Language**: Go 1.24 | **Duration**: 2 months of development  
> **Repository**: [metachat-main](file:///c:/Users/user/Desktop/Unime%20-%20Data%20Analysis/metachat-main)

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Why End-to-End Encryption?](#2-why-end-to-end-encryption)
3. [System Architecture (Web Programming)](#3-system-architecture-web-programming)
4. [Cryptographic Foundations (Security)](#4-cryptographic-foundations-security)
5. [Code Walkthrough](#5-code-walkthrough)
6. [Step-by-Step Message Flow](#6-step-by-step-message-flow)
7. [Security Analysis](#7-security-analysis)
8. [Comparison to Signal Protocol](#8-comparison-to-signal-protocol)
9. [Professor Q&A Preparation](#9-professor-qa-preparation)

---

## 1. Project Overview

MetaChat is a **minimal but fully functional** end-to-end encrypted messaging system built entirely in Go. It demonstrates how modern secure messaging (like Signal or WhatsApp) works at a fundamental level.

### What We Built

| Component | Description | File |
|-----------|-------------|------|
| **Relay Server** | HTTP API + Redis backend that stores/forwards encrypted data | [server/main.go](file:///c:/Users/user/Desktop/Unime%20-%20Data%20Analysis/metachat-main/server/main.go) |
| **Sender Client (Matteo)** | Fetches keys, encrypts, sends messages | [matteo/main.go](file:///c:/Users/user/Desktop/Unime%20-%20Data%20Analysis/metachat-main/matteo/main.go) |
| **Receiver Client (Benny)** | Generates keys, polls for messages, decrypts | [benny/main.go](file:///c:/Users/user/Desktop/Unime%20-%20Data%20Analysis/metachat-main/benny/main.go) |
| **Crypto Library** | X25519, HKDF-SHA256, AES-256-GCM functions | [internal/crypto/crypto.go](file:///c:/Users/user/Desktop/Unime%20-%20Data%20Analysis/metachat-main/internal/crypto/crypto.go) |
| **Ratchet Engine** | Double Ratchet key derivation chain | [internal/ratchet/ratchet.go](file:///c:/Users/user/Desktop/Unime%20-%20Data%20Analysis/metachat-main/internal/ratchet/ratchet.go) |

### The Core Principle

> **The server NEVER sees plaintext.** It only stores opaque ciphertext blobs and public keys. Even if the server is compromised, all messages remain encrypted and unreadable.

---

## 2. Why End-to-End Encryption?

### The Problem with Traditional Messaging

In a traditional messaging system:
```
Sender → [plaintext] → Server (stores plaintext) → [plaintext] → Receiver
```

**Anyone** with access to the server database (hackers, server admins, government agencies via court orders) can read ALL messages.

### The E2EE Solution

With End-to-End Encryption:
```
Sender → [encrypt locally] → Server (stores ciphertext only) → [decrypt locally] → Receiver
```

The message is **encrypted on the sender's device** and **decrypted only on the receiver's device**. The server in between is just a "delivery man" — it carries the locked box but **does not have the key**.

### Real-World Adoption

| App | E2EE by Default | Protocol | Notes |
|-----|----------------|----------|-------|
| Signal | ✅ Yes | Signal Protocol | Open source, gold standard |
| WhatsApp | ✅ Yes | Signal Protocol | Uses Signal's library |
| Telegram | ❌ No | MTProto | E2EE only in "Secret Chats" |
| iMessage | ✅ Yes | Custom (Apple) | Closed source |
| Facebook Messenger | ✅ Yes | Signal Protocol | Default since Dec 2023 |

---

## 3. System Architecture (Web Programming)

### 3.1 Client-Server Design

MetaChat uses a **three-process architecture** communicating over HTTP:

```
┌──────────┐          ┌──────────────────┐          ┌──────────┐
│          │  HTTP    │                  │  HTTP    │          │
│  Matteo  │ ──────→ │   Relay Server   │ ←────── │  Benny   │
│ (sender) │         │  (HTTP + Redis)  │         │(receiver)│
│          │         │                  │         │          │
└──────────┘         └──────────────────┘         └──────────┘
```

- **Matteo** and **Benny** are independent CLI clients
- The **Server** is a standard HTTP server using Go's `net/http` package
- **Redis** provides persistent storage for keys and message queues

### 3.2 Technology Stack

| Technology | Role | Why We Chose It |
|-----------|------|-----------------|
| **Go 1.24** | Backend language | Fast, compiled, excellent crypto stdlib, strong concurrency |
| **net/http** (stdlib) | HTTP server & client | No external framework needed, built into Go |
| **encoding/json** (stdlib) | Data serialization | Standard JSON for REST API payloads |
| **Redis** | Data store | In-memory speed, native list operations (perfect for message queues) |
| **golang.org/x/crypto** | Cryptographic primitives | Official Go crypto extensions (X25519, HKDF) |

### 3.3 Server REST API

The relay server exposes **4 HTTP endpoints**:

#### `POST /upload_prekey?user=X`
**Purpose**: Upload a user's public key bundle (prekey)

```json
// Request Body
{
  "identity_key": [32 bytes, base64-encoded]
}
```
- Validates key length (must be exactly 32 bytes)
- Stores in Redis as `prekey:<user>` (String type)
- Returns `"OK"` on success

#### `GET /prekey?user=X`
**Purpose**: Fetch a user's public key

- Reads from Redis key `prekey:<user>`
- Returns JSON with the public key bundle
- Returns HTTP 404 if no key found

#### `POST /send_secure?to=X`
**Purpose**: Queue an encrypted message for a recipient

```json
// Request Body (SecureMessage)
{
  "from_identity": [32 bytes],    // Sender's public key
  "ephemeral_key": [32 bytes],    // Sender's ephemeral DH public key
  "nonce":         [12 bytes],    // AES-GCM nonce
  "ciphertext":    [variable]     // AES-GCM sealed message + auth tag
}
```
- Validates that ciphertext and nonce are non-empty
- Pushes to Redis list `secure_mailbox:<to>` using `LPUSH`
- The server **never** inspects or decrypts any fields

#### `GET /fetch_secure?user=X`
**Purpose**: Pop the next encrypted message from a user's mailbox

- Uses Redis `RPOP` on `secure_mailbox:<user>` (FIFO ordering with LPUSH/RPOP)
- Returns empty JSON `{}` if no messages waiting
- Returns the full SecureMessage JSON if a message exists

### 3.4 Redis Data Model

| Redis Key | Type | Contents |
|-----------|------|----------|
| `prekey:benny` | String | JSON-encoded `PrekeyBundle` with 32-byte public key |
| `secure_mailbox:benny` | List | Queue of JSON-encoded `SecureMessage` objects |

> [!IMPORTANT]
> Redis is used as a **message queue** here. `LPUSH` adds to the left (head) and `RPOP` removes from the right (tail), creating a FIFO (First-In-First-Out) queue. This means messages are delivered in the order they were sent.

---

## 4. Cryptographic Foundations (Security)

This is the heart of the project. We use four cryptographic building blocks that, when combined, create a secure messaging pipeline.

### 4.1 Curve25519 — The Elliptic Curve

#### What is Curve25519?

Curve25519 is an **elliptic curve** designed by Daniel J. Bernstein in 2005/2006. It is defined as a **Montgomery curve** with the equation:

```
y² = x³ + 486662·x² + x    (mod p)
```

where **p = 2²⁵⁵ − 19** (hence the name "25519").

#### Why is it called "25519"?

The name comes from the prime number used: **2²⁵⁵ − 19**. This is a Mersenne-like prime chosen specifically because:

1. **Fast arithmetic**: The form `2^n - c` (with small `c`) allows extremely fast modular reduction
2. **255-bit security**: Provides approximately 128 bits of security (half the bit length, as per standard ECC security estimates)
3. **The `−19`**: Makes the prime congruent to 5 mod 8, which gives useful algebraic properties for square root computation on the curve

#### Why is the coefficient 486662?

The coefficient `A = 486662` in the Montgomery form `y² = x³ + Ax² + x` was chosen by Bernstein because:
- It's the **smallest positive integer** `A` such that `(A-2)/4` is a small integer AND the curve has the right security properties (safe prime-order subgroup)
- `(486662 - 2) / 4 = 121665`, which is used in the internal arithmetic
- The curve's group order factors as `8 × (a large prime)`, giving a cofactor of 8

#### Key Properties

| Property | Value |
|----------|-------|
| Curve type | Montgomery |
| Prime field | p = 2²⁵⁵ − 19 |
| Coefficient A | 486662 |
| Base point (u-coordinate) | 9 |
| Group order | 2²⁵² + 27742317777372353535851937790883648493 |
| Cofactor | 8 |
| Security level | ~128 bits |
| Key size | 32 bytes (256 bits) |

#### Why Curve25519 over RSA or other curves?

| Aspect | Curve25519 | RSA-2048 | NIST P-256 |
|--------|-----------|----------|------------|
| Key size | 32 bytes | 256 bytes | 32 bytes |
| Speed | Very fast | Slow | Moderate |
| Side-channel resistance | Designed in | Must be added | Must be added |
| Trust | Transparent design | Trusted | NSA-designed (some distrust) |
| Constant-time | By design | Difficult | Difficult |

Curve25519 was **designed from the ground up** to be:
- **Fast**: One of the fastest elliptic curves
- **Secure against side-channel attacks**: Constant-time by design (no timing leaks)
- **Simple to implement correctly**: Fewer ways to make implementation mistakes
- **Transparent**: Every design choice has a clear mathematical justification (no "nothing up my sleeve" concerns)

---

### 4.2 X25519 — Diffie-Hellman Key Exchange

#### What is X25519?

**X25519** is the **Diffie-Hellman function** using Curve25519. The "X" prefix means it operates only on the **x-coordinate** of curve points (this is the Montgomery ladder, which is faster and simpler than full-point arithmetic).

#### How Diffie-Hellman Works (The Paint Analogy)

Imagine Alice and Bob want to agree on a shared color, but Eve is watching:

1. They publicly agree on a common base color (yellow)
2. Alice picks a secret color (red) and mixes: yellow + red = orange → sends orange publicly
3. Bob picks a secret color (blue) and mixes: yellow + blue = green → sends green publicly
4. Alice mixes: green + red = **brown** (the shared secret)
5. Bob mixes: orange + blue = **brown** (the same shared secret!)
6. Eve sees yellow, orange, green — but **cannot derive brown** without knowing red or blue

#### The Math Behind X25519

In elliptic curve terms:
```
Matteo: private_key_m = random 32 bytes
        public_key_m  = private_key_m × G    (scalar multiplication with base point G)

Benny:  private_key_b = random 32 bytes
        public_key_b  = private_key_b × G    (scalar multiplication with base point G)

Shared secret (Matteo computes): S = private_key_m × public_key_b
                                   = private_key_m × (private_key_b × G)
                                   = (private_key_m × private_key_b) × G

Shared secret (Benny computes):  S = private_key_b × public_key_m
                                   = private_key_b × (private_key_m × G)
                                   = (private_key_b × private_key_m) × G

Both equal: (private_key_m × private_key_b) × G = same point!
```

The **Elliptic Curve Discrete Logarithm Problem (ECDLP)** makes it computationally infeasible to derive the private key from the public key.

#### Our Implementation

```go
// In internal/crypto/crypto.go

func GenerateKeyPair() (priv, pub []byte) {
    priv = make([]byte, 32)          // 32 random bytes from OS CSPRNG
    rand.Read(priv)                   // crypto/rand — secure randomness
    pub, _ = curve25519.X25519(priv, curve25519.Basepoint)  // pub = priv × G
    return
}

func DH(priv, pub []byte) []byte {
    shared, _ := curve25519.X25519(priv, pub)  // shared = priv × remotePub
    return shared
}
```

- `curve25519.Basepoint` is the fixed base point (u=9) of Curve25519
- `curve25519.X25519()` performs scalar multiplication on the curve
- The output is a 32-byte shared secret

---

### 4.3 HKDF-SHA256 — Key Derivation

#### Why Do We Need Key Derivation?

The raw shared secret from X25519 is **not suitable** for direct use as an encryption key because:
1. It may have **biased bits** (not uniformly random)
2. We need **multiple keys** from a single secret (root key, chain key, message key)
3. We need **domain separation** (keys for different purposes must be independent)

#### What is HKDF?

**HKDF** (HMAC-based Key Derivation Function, defined in [RFC 5869](https://tools.ietf.org/html/rfc5869)) has two phases:

1. **Extract**: Takes the input key material (IKM) and an optional salt, produces a pseudorandom key (PRK)
   ```
   PRK = HMAC-SHA256(salt, IKM)
   ```

2. **Expand**: Takes the PRK and an info string, produces output key material (OKM) of desired length
   ```
   OKM = HMAC-SHA256(PRK, info || 0x01)
   ```

The **info** parameter provides **domain separation** — using different info strings ("root", "chain", "msg") from the same secret produces completely independent keys.

#### Our Implementation

```go
func HKDF(secret []byte, info string) []byte {
    h := hkdf.New(sha256.New, secret, nil, []byte(info))  // nil salt = zeros
    out := make([]byte, 32)                                 // 32-byte output
    io.ReadFull(h, out)                                     // read exactly 32 bytes
    return out
}
```

#### Key Derivation Chain in MetaChat

```
Shared Secret (from X25519 DH)
    │
    ▼
Root Key    = HKDF(shared_secret, "root")      ← domain: "root"
    │
    ▼
Chain Key   = HKDF(root_key, "chain")          ← domain: "chain"
    │
    ▼
Chain Key'  = HKDF(chain_key, "chain-step")    ← advance the chain
    │
    ▼
Message Key = HKDF(chain_key', "msg")          ← domain: "msg"
```

Each key is derived deterministically but independently. Knowing the message key does NOT let you compute the root key or chain key.

---

### 4.4 Double Ratchet — Forward Secrecy

#### What is Forward Secrecy?

**Forward secrecy** means: if an attacker compromises the current encryption keys, they **cannot decrypt past messages**. This is critical because:

- If a device is seized today, messages from yesterday should remain private
- The Signal Protocol provides this property, and MetaChat implements a simplified version

#### How the Ratchet Works

Think of a ratchet wrench — it only moves **forward**, never backward:

```
Chain Key₀ ──HKDF("chain-step")──→ Chain Key₁ ──HKDF("chain-step")──→ Chain Key₂ ...
                                        │                                    │
                                   HKDF("msg")                          HKDF("msg")
                                        │                                    │
                                        ▼                                    ▼
                                   Message Key₁                         Message Key₂
```

After deriving Message Key₁, Chain Key₀ is **overwritten** with Chain Key₁. There is no way to go back from Chain Key₁ to Chain Key₀. This is forward secrecy.

#### Our Implementation

```go
type Ratchet struct {
    RootKey   []byte   // Current root key
    ChainKey  []byte   // Current chain key (advances forward)
    DHPriv    []byte   // Current DH private key
    DHPub     []byte   // Current DH public key
    RemotePub []byte   // Remote party's public key
}

func NewRatchet(sharedSecret, remotePub []byte) *Ratchet {
    priv, pub := crypto.GenerateKeyPair()           // Fresh DH keypair for ratchet
    root := crypto.HKDF(sharedSecret, "root")       // Derive root key
    chain := crypto.HKDF(root, "chain")             // Derive initial chain key
    return &Ratchet{
        RootKey: root, ChainKey: chain,
        DHPriv: priv, DHPub: pub, RemotePub: remotePub,
    }
}

func (r *Ratchet) NextMessageKey() []byte {
    r.ChainKey = crypto.HKDF(r.ChainKey, "chain-step")  // Advance chain (old key GONE)
    return crypto.HKDF(r.ChainKey, "msg")                // Derive message key
}

func (r *Ratchet) RatchetStep() {
    dhOut := crypto.DH(r.DHPriv, r.RemotePub)            // New DH exchange
    r.RootKey = crypto.HKDF(dhOut, "root")               // New root key
    r.ChainKey = crypto.HKDF(r.RootKey, "chain")         // New chain key
    r.DHPriv, r.DHPub = crypto.GenerateKeyPair()         // Fresh DH keys
}
```

#### The DH Ratchet Step (Future Secrecy)

The `RatchetStep()` method provides **future secrecy** (also called "break-in recovery"):
- It generates a completely **new DH keypair**
- Performs a fresh DH exchange to derive new root and chain keys
- Even if the current state is compromised, future messages (after a ratchet step) become secure again

---

### 4.5 AES-256-GCM — Authenticated Encryption

#### What is AES-256-GCM?

**AES-256-GCM** (Advanced Encryption Standard, 256-bit key, Galois/Counter Mode) provides two things simultaneously:

1. **Confidentiality**: The plaintext is encrypted — nobody without the key can read it
2. **Integrity/Authentication**: A 16-byte **authentication tag** is appended — if even 1 bit of the ciphertext is modified, decryption **fails**

#### Components

| Component | Size | Purpose |
|-----------|------|---------|
| Key | 32 bytes (256 bits) | The AES encryption key (from ratchet's message key) |
| Nonce (IV) | 12 bytes (96 bits) | "Number used once" — must be unique per encryption |
| Plaintext | Variable | The original message |
| Ciphertext | Same as plaintext | The encrypted message |
| Auth Tag | 16 bytes (128 bits) | Authentication tag (appended to ciphertext by `Seal`) |

#### Why GCM Mode?

- **Counter Mode (CTR)**: Turns AES (a block cipher) into a stream cipher — encrypts data of any length
- **Galois (G)**: Adds polynomial multiplication in GF(2¹²⁸) to compute the authentication tag
- **Combined**: Encryption + authentication in a single pass — very efficient

#### Our Implementation

```go
func Encrypt(key, plaintext []byte) (nonce, ciphertext []byte) {
    block, _ := aes.NewCipher(key)         // Create AES-256 cipher (key must be 32 bytes)
    gcm, _ := cipher.NewGCM(block)         // Wrap in GCM mode
    nonce = make([]byte, gcm.NonceSize())  // 12 bytes
    rand.Read(nonce)                        // Random nonce from OS CSPRNG
    ciphertext = gcm.Seal(nil, nonce, plaintext, nil)  // Encrypt + auth tag
    return
}

func Decrypt(key, nonce, ciphertext []byte) []byte {
    block, _ := aes.NewCipher(key)
    gcm, _ := cipher.NewGCM(block)
    plaintext, _ := gcm.Open(nil, nonce, ciphertext, nil)  // Decrypt + verify tag
    return plaintext
}
```

- `gcm.Seal()` returns `ciphertext || auth_tag` (tag is appended automatically)
- `gcm.Open()` verifies the tag first — if verification fails, it returns `nil` and an error
- The `nil` in the last parameter is AAD (Additional Authenticated Data) — we don't use it here

> [!WARNING]
> **Nonce reuse is catastrophic!** If you ever encrypt two different messages with the same key AND the same nonce, AES-GCM breaks completely — an attacker can XOR the two ciphertexts and recover both plaintexts. This is why we generate a **random 12-byte nonce** for every single message.

---

## 5. Code Walkthrough

### 5.1 Crypto Module — [crypto.go](file:///c:/Users/user/Desktop/Unime%20-%20Data%20Analysis/metachat-main/internal/crypto/crypto.go)

**54 lines** — Four core functions:

| Function | Input | Output | What It Does |
|----------|-------|--------|-------------|
| `GenerateKeyPair()` | — | (priv, pub) | 32 random bytes → X25519 scalar mult with base point |
| `DH(priv, pub)` | Private key + remote public key | 32-byte shared secret | X25519 Diffie-Hellman exchange |
| `HKDF(secret, info)` | Key material + domain label | 32-byte derived key | HKDF-SHA256 key derivation |
| `Encrypt(key, plaintext)` | 32-byte key + message | (nonce, ciphertext) | AES-256-GCM encryption |
| `Decrypt(key, nonce, ciphertext)` | key + nonce + ciphertext | plaintext | AES-256-GCM decryption |

Dependencies: `crypto/aes`, `crypto/cipher`, `crypto/rand`, `crypto/sha256` (all stdlib) + `golang.org/x/crypto/hkdf`, `golang.org/x/crypto/curve25519`.

### 5.2 Ratchet Module — [ratchet.go](file:///c:/Users/user/Desktop/Unime%20-%20Data%20Analysis/metachat-main/internal/ratchet/ratchet.go)

**37 lines** — The Double Ratchet state machine:

| Component | Purpose |
|-----------|---------|
| `Ratchet` struct | Holds RootKey, ChainKey, DH keypair, remote public key |
| `NewRatchet()` | Initializes ratchet from a shared secret |
| `NextMessageKey()` | Advances chain key and derives message key |
| `RatchetStep()` | Full DH ratchet — new DH exchange + new root/chain keys |

### 5.3 Server — [server/main.go](file:///c:/Users/user/Desktop/Unime%20-%20Data%20Analysis/metachat-main/server/main.go)

**134 lines** — The zero-knowledge relay:

Key design decisions:
- Server defines `PrekeyBundle` and `SecureMessage` structs for JSON parsing
- Uses `http.HandleFunc` for routing (4 endpoints)
- Redis client initialized at startup with connectivity check
- **No decryption functions imported** — the server package doesn't import `internal/crypto`
- All error cases return appropriate HTTP status codes (400, 404, 500)
- Logging shows operations without exposing sensitive data

### 5.4 Sender: Matteo — [matteo/main.go](file:///c:/Users/user/Desktop/Unime%20-%20Data%20Analysis/metachat-main/matteo/main.go)

**124 lines** — The encryption pipeline:

1. Read message from CLI args or stdin (interactive mode)
2. `GET /prekey?user=benny` → Fetch Benny's public key
3. `GenerateKeyPair()` → Create ephemeral X25519 keypair
4. `DH(matteoPriv, bundle.IdentityKey)` → Compute shared secret
5. `NewRatchet(shared, ...)` + `NextMessageKey()` → Derive message key
6. `Encrypt(msgKey, plaintext)` → AES-256-GCM encryption
7. `POST /send_secure?to=benny` → Send `{from_identity, ephemeral_key, nonce, ciphertext}`

### 5.5 Receiver: Benny — [benny/main.go](file:///c:/Users/user/Desktop/Unime%20-%20Data%20Analysis/metachat-main/benny/main.go)

**92 lines** — The decryption pipeline:

1. `GenerateKeyPair()` → Create X25519 identity keypair
2. `POST /upload_prekey?user=benny` → Upload public key to server
3. **Polling loop**: `GET /fetch_secure?user=benny` every 300ms
4. When message arrives:
   - `DH(bennyPriv, msg.EphemeralKey)` → Compute same shared secret
   - `NewRatchet(shared, ...)` + `NextMessageKey()` → Derive same message key
   - `Decrypt(msgKey, msg.Nonce, msg.Ciphertext)` → Recover plaintext

---

## 6. Step-by-Step Message Flow

### Complete Sequence

```
Step  Who → Where         Action                                What Travels
────  ──────────────────  ──────────────────────────────────────  ──────────────
 1    Benny (local)       Generate X25519 identity keypair       Nothing
 2    Benny → Server      POST /upload_prekey                    Public key (32 bytes)
 3    Matteo → Server     GET /prekey?user=benny                 Nothing
 4    Server → Matteo     Response                               Public key (32 bytes)
 5    Matteo (local)      Generate ephemeral X25519 keypair      Nothing
 6    Matteo (local)      DH: shared = X25519(m_priv, b_pub)    Nothing (computed locally)
 7    Matteo (local)      Ratchet → derive message key           Nothing (computed locally)
 8    Matteo (local)      AES-GCM encrypt                        Nothing (computed locally)
 9    Matteo → Server     POST /send_secure?to=benny             {eph_pub, nonce, ciphertext}
10    Server              LPUSH to secure_mailbox:benny          Stored as opaque blob
11    Benny → Server      GET /fetch_secure?user=benny           Nothing
12    Server → Benny      Response                               {eph_pub, nonce, ciphertext}
13    Benny (local)       DH: shared = X25519(b_priv, m_eph)    Nothing (computed locally)
14    Benny (local)       Ratchet → derive SAME message key      Nothing (computed locally)
15    Benny (local)       AES-GCM decrypt → plaintext!           Nothing (stays on device)
```

### What the Server Sees

The server only ever sees:
- Benny's **public key** (safe — that's what "public" means)
- A JSON blob: `{from_identity, ephemeral_key, nonce, ciphertext}`
- It has **NO access** to: shared secrets, root keys, chain keys, message keys, or plaintext

### Terminal Output (Live Demo)

**Terminal 1 — Server:**
```
[SERVER] Running on :8080 (Redis: localhost:6379)
[SERVER] Stored prekey bundle for benny (Redis key: prekey:benny)
[SERVER] Served prekey bundle for benny
[SERVER] Queued secure message for benny (Redis list: secure_mailbox:benny)
[SERVER] Delivered 1 secure message to benny
```

**Terminal 2 — Benny:**
```
[BENNY] Generating Benny X25519 identity keypair...
[BENNY] Uploading Benny public key to server (stored in Redis as prekey:benny)...
[BENNY] Benny ready. Polling mailbox from server (secure_mailbox:benny in Redis)...
[BENNY] Received encrypted message. Deriving shared secret (X25519 DH)...
[BENNY] Initializing ratchet and deriving message key...
[BENNY] Decrypting with AES-GCM...
[BENNY] Benny received: Hello Benny, this is a secret message!
```

**Terminal 3 — Matteo:**
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

---

## 7. Security Analysis

### What We Implemented ✅

| Property | Implementation | Details |
|----------|---------------|---------|
| **Authenticated Encryption** | ✅ AES-256-GCM | Provides confidentiality + integrity |
| **Key Exchange** | ✅ X25519 ECDH | Industry standard, ~128-bit security |
| **Forward Secrecy** | ✅ Chain key ratcheting | Old chain keys are overwritten |
| **Zero-Knowledge Server** | ✅ Ciphertext-only relay | Server never imports crypto module |
| **Secure Randomness** | ✅ `crypto/rand` | OS-level CSPRNG (not `math/rand`) |

### What We Did NOT Implement ❌ (Educational Scope)

| Missing Feature | Why It Matters | How to Add |
|-----------------|---------------|------------|
| **TLS** | HTTP traffic is unencrypted in transit | Use `http.ListenAndServeTLS()` with certificates |
| **Identity Verification** | No way to verify you're talking to the real person (MITM risk) | Safety numbers, QR code verification, certificate pinning |
| **Replay Protection** | An attacker could re-send the same ciphertext | Message counters + sequence numbers |
| **Key Persistence** | Keys regenerated every run | Secure key storage (file-based or OS keychain) |
| **Multi-Message** | Benny exits after one message | Keep polling loop running |
| **Group Messaging** | Only 1-to-1 | Sender Keys protocol (like Signal groups) |

### Attack Scenarios

| Attack | Protected? | Explanation |
|--------|-----------|-------------|
| Server reads messages | ✅ Yes | Server has only ciphertext, no keys |
| Database breach | ✅ Yes | Only ciphertext blobs in Redis |
| Ciphertext tampering | ✅ Yes | AES-GCM auth tag fails on modification |
| Man-in-the-Middle | ❌ No | No identity verification mechanism |
| Replay attack | ❌ No | No message counters |
| Traffic analysis | ❌ No | Message sizes and timing are visible |

---

## 8. Comparison to Signal Protocol

### Signal Protocol Architecture

The Signal Protocol (used by Signal, WhatsApp, FB Messenger) has three main components:

1. **X3DH (Extended Triple Diffie-Hellman)**: Initial key agreement
   - Uses 3 DH computations with identity keys, signed prekeys, and one-time prekeys
   - Allows asynchronous setup (parties don't need to be online simultaneously)

2. **Double Ratchet**: Ongoing message encryption
   - Symmetric-key ratchet (chain key advancement) — **we implement this**
   - DH ratchet (new DH exchange per message turn) — **we partially implement this**
   - Header encryption for metadata privacy — **we don't implement this**

3. **Sesame**: Multi-device key management — **we don't implement this**

### MetaChat vs Signal Protocol

| Feature | Signal Protocol | MetaChat |
|---------|----------------|----------|
| Initial key exchange | X3DH (3 DH computations) | Single DH (simplified) |
| Chain ratchet | ✅ Full | ✅ Implemented |
| DH ratchet | ✅ Per-turn | ✅ Implemented (RatchetStep) |
| Header encryption | ✅ Yes | ❌ No |
| Identity verification | ✅ Safety numbers | ❌ No |
| Prekey bundles | ✅ Signed + one-time | ✅ Simple public key |
| Multi-device | ✅ Yes | ❌ No |
| Group messaging | ✅ Sender Keys | ❌ No |

> [!NOTE]
> MetaChat implements the **core cryptographic ideas** of Signal in a simplified form. The key insight is the same: combine DH key exchange with a ratcheting key derivation chain and authenticated encryption, relaying through a zero-knowledge server.

---

## 9. Professor Q&A Preparation

### Likely Questions and Answers

#### Q: "Why did you choose Curve25519 instead of RSA or NIST P-256?"
**A**: Curve25519 is faster, has smaller keys (32 bytes vs 256 bytes for RSA-2048), and was designed to be resistant to side-channel attacks by construction. Unlike NIST P-256 (which was designed by NSA and has some community distrust), Curve25519's design parameters are fully transparent — every constant has a clear mathematical justification.

#### Q: "What is forward secrecy and does your system provide it?"
**A**: Forward secrecy means that if an attacker gets the current encryption keys, they cannot decrypt past messages. Yes, our system provides this through the chain key ratchet: each call to `NextMessageKey()` advances the chain key using HKDF, and the old chain key is overwritten in memory. Since HKDF is a one-way function, you cannot go backwards from the new chain key to the old one.

#### Q: "Why do you use HKDF instead of using the shared secret directly as the AES key?"
**A**: The raw DH shared secret may have biased bits and shouldn't be used directly. HKDF serves three purposes: (1) it produces uniformly distributed key material, (2) it allows us to derive multiple independent keys from one secret using different "info" labels, and (3) it provides domain separation — the "root" key is cryptographically independent from the "chain" key even though they come from the same shared secret.

#### Q: "What happens if someone tampers with the ciphertext?"
**A**: AES-GCM includes a 16-byte authentication tag. When Benny tries to decrypt, `gcm.Open()` first verifies this tag. If even a single bit of the ciphertext has been modified, verification fails and the function returns nil + error. We tested this: manually modifying the ephemeral key in Redis causes authentication failure.

#### Q: "Why Redis and not a regular database?"
**A**: Redis is an in-memory data store, which gives us extremely fast reads and writes. More importantly, Redis has native **list operations** (`LPUSH`/`RPOP`) that naturally implement a FIFO message queue. This is exactly what we need for an asynchronous mailbox system. A traditional SQL database would work but would require more complex query logic.

#### Q: "What is the biggest security weakness of your system?"
**A**: The biggest weakness is the lack of **identity verification**. Our system has no way to verify that the public key received from the server actually belongs to Benny. A Man-in-the-Middle (MITM) attacker could substitute their own public key. In production, this is solved with safety numbers (like Signal), certificate pinning, or Trust-On-First-Use (TOFU).

#### Q: "Why Go?"
**A**: Go has several advantages for this project: (1) excellent standard library with `crypto/aes`, `crypto/cipher`, `crypto/rand`, (2) official `golang.org/x/crypto` package with X25519 and HKDF, (3) simple HTTP server with `net/http`, (4) fast compilation and execution, (5) strong typing catches many errors at compile time.

#### Q: "How does the server remain zero-knowledge?"
**A**: The server package (`server/main.go`) does not import `internal/crypto` at all. It only uses `encoding/json` and `net/http`. It treats every field in the SecureMessage as opaque bytes — it serializes and deserializes them for storage, but never performs any cryptographic operations. The server literally cannot decrypt because it doesn't have the code to do so.

#### Q: "What is the nonce and why is it important?"
**A**: The nonce ("number used once") is a 12-byte random value generated fresh for each encryption. AES-GCM requires that you NEVER reuse a nonce with the same key. If you do (called "nonce reuse" or "nonce misuse"), an attacker can XOR the two ciphertexts and potentially recover both plaintexts. We use `crypto/rand` (OS-level CSPRNG) to generate random nonces, making collision probability negligibly small (~2⁻⁴⁸ for 12-byte nonces).

#### Q: "What is the difference between encryption and authenticated encryption?"
**A**: Regular encryption (like AES-CTR) only provides **confidentiality** — nobody can read the message without the key. But an attacker could still **modify** the ciphertext, and the receiver would decrypt it into garbage without knowing it was tampered with. Authenticated encryption (AES-GCM) adds an authentication tag that lets the receiver detect ANY modification. This is why GCM is preferred over plain CTR mode.

#### Q: "How would you make this production-ready?"
**A**: We would need to add: (1) TLS for client-server communication, (2) identity verification (safety numbers or certificates), (3) message counters for replay protection, (4) persistent key storage, (5) full X3DH for initial key exchange, (6) header encryption for metadata privacy, (7) multi-device support, and (8) proper error handling and logging.

---

> [!TIP]
> **Presentation Tips**: 
> - Press **S** in the presentation to open Speaker Notes view
> - Speaker notes contain suggested talking points for each slide
> - The presentation covers both the **web programming** (architecture, API, Redis) and **security** (cryptography) aspects
> - Be prepared to show a live demo: start Redis → start server → start Benny → run Matteo
