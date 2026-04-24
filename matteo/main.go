package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

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
	message, err := readMessage()
	if err != nil {
		fmt.Println("[MATTEO] Error reading message:", err)
		os.Exit(1)
	}

	// Fetch Benny prekey
	fmt.Println("[MATTEO] Fetching Benny prekey from server...")
	resp, err := http.Get("http://localhost:8080/prekey?user=benny")
	if err != nil {
		fmt.Println("[MATTEO] Error fetching prekey:", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Println("[MATTEO] Server did not return Benny prekey. Status:", resp.Status)
		fmt.Println("[MATTEO] Run `go run ./benny` first to upload Benny's key.")
		os.Exit(1)
	}
	var bundle PrekeyBundle
	if err := json.NewDecoder(resp.Body).Decode(&bundle); err != nil {
		fmt.Println("[MATTEO] Error decoding prekey bundle:", err)
		os.Exit(1)
	}
	if len(bundle.IdentityKey) != 32 {
		fmt.Println("[MATTEO] Invalid Benny identity key length:", len(bundle.IdentityKey))
		os.Exit(1)
	}
	fmt.Println("[MATTEO] Benny prekey received.")

	// Matteo ephemeral key
	fmt.Println("[MATTEO] Generating Matteo ephemeral X25519 keypair...")
	matteoPriv, matteoPub := crypto.GenerateKeyPair()

	fmt.Println("[MATTEO] Computing shared secret (X25519 DH)...")
	shared := crypto.DH(matteoPriv, bundle.IdentityKey)
	fmt.Println("[MATTEO] Initializing ratchet and deriving message key...")
	r := ratchet.NewRatchet(shared, bundle.IdentityKey)
	msgKey := r.NextMessageKey()

	fmt.Println("[MATTEO] Encrypting message with AES-GCM...")
	nonce, ciphertext := crypto.Encrypt(msgKey, []byte(message))

	msg := SecureMessage{
		FromIdentity: matteoPub,
		EphemeralKey: matteoPub,
		Nonce:        nonce,
		Ciphertext:   ciphertext,
	}

	fmt.Println("[MATTEO] Sending encrypted message to server (queued for benny in Redis)...")
	data, err := json.Marshal(msg)
	if err != nil {
		fmt.Println("[MATTEO] Error encoding secure message:", err)
		os.Exit(1)
	}
	sendResp, err := http.Post("http://localhost:8080/send_secure?to=benny",
		"application/json", bytes.NewBuffer(data))
	if err != nil {
		fmt.Println("[MATTEO] Error sending secure message:", err)
		os.Exit(1)
	}
	defer sendResp.Body.Close()
	if sendResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(sendResp.Body)
		fmt.Println("[MATTEO] Server rejected message. Status:", sendResp.Status, "Body:", string(body))
		os.Exit(1)
	}

	fmt.Println("[MATTEO] Done. Message sent.")
}

func readMessage() (string, error) {
	if len(os.Args) > 1 {
		msg := strings.TrimSpace(strings.Join(os.Args[1:], " "))
		if msg == "" {
			return "", errors.New("message is empty")
		}
		fmt.Println("[MATTEO] Message from CLI args:", msg)
		return msg, nil
	}

	fmt.Print("[MATTEO] Type a message to Benny and press Enter: ")
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	msg := strings.TrimSpace(line)
	if msg == "" {
		return "", errors.New("message is empty")
	}
	return msg, nil
}
