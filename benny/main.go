package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"metachat/internal/crypto"
	"metachat/internal/ratchet"
)

type PrekeyBundle struct {
	IdentityKey []byte `json:"identity_key"`
}

type SecureMessage struct {
	FromIdentity []byte `json:"from_identity"`
	EphemeralKey []byte `json:"ephemeral_key"`
	Nonce        []byte `json:"nonce"`
	Ciphertext   []byte `json:"ciphertext"`
}

func main() {
	// Benny identity
	fmt.Println("[BENNY] Generating Benny X25519 identity keypair...")
	bennyPriv, bennyPub := crypto.GenerateKeyPair()

	// Upload public key
	fmt.Println("[BENNY] Uploading Benny public key to server (stored in Redis as prekey:benny)...")
	bundle := PrekeyBundle{IdentityKey: bennyPub}
	data, err := json.Marshal(bundle)
	if err != nil {
		fmt.Println("[BENNY] Error encoding prekey bundle:", err)
		os.Exit(1)
	}
	resp, err := http.Post("http://localhost:8080/upload_prekey?user=benny",
		"application/json", bytes.NewBuffer(data))
	if err != nil {
		fmt.Println("[BENNY] Error uploading prekey bundle:", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		fmt.Println("[BENNY] Server rejected prekey upload. Status:", resp.Status, "Body:", string(body))
		os.Exit(1)
	}

	fmt.Println("[BENNY] Benny ready. Polling mailbox from server (secure_mailbox:benny in Redis)...")

	for {
		resp, err := http.Get("http://localhost:8080/fetch_secure?user=benny")
		if err != nil {
			fmt.Println("[BENNY] Error fetching secure message:", err)
			time.Sleep(500 * time.Millisecond)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			time.Sleep(500 * time.Millisecond)
			continue
		}

		var msg SecureMessage
		if err := json.NewDecoder(resp.Body).Decode(&msg); err != nil {
			resp.Body.Close()
			time.Sleep(300 * time.Millisecond)
			continue
		}
		resp.Body.Close()
		if len(msg.Ciphertext) == 0 {
			time.Sleep(300 * time.Millisecond)
			continue
		}

		fmt.Println("[BENNY] Received encrypted message. Deriving shared secret (X25519 DH)...")
		shared := crypto.DH(bennyPriv, msg.EphemeralKey)
		fmt.Println("[BENNY] Initializing ratchet and deriving message key...")
		r := ratchet.NewRatchet(shared, msg.EphemeralKey)
		msgKey := r.NextMessageKey()

		fmt.Println("[BENNY] Decrypting with AES-GCM...")
		plaintext := crypto.Decrypt(msgKey, msg.Nonce, msg.Ciphertext)
		fmt.Println("[BENNY] Benny received:", string(plaintext))
		break
	}
}
