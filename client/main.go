package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"metachat/internal/crypto"
	"metachat/internal/ratchet"
)

type PrekeyBundle struct {
	IdentityKey []byte `json:"identity_key"`
}

type SecureMessage struct {
	FromUser     string `json:"from_user,omitempty"`
	FromIdentity []byte `json:"from_identity"`
	EphemeralKey []byte `json:"ephemeral_key"`
	Nonce        []byte `json:"nonce"`
	Ciphertext   []byte `json:"ciphertext"`
}

type UsersResponse struct {
	Users []string `json:"users"`
}

type ContactsResponse struct {
	User     string   `json:"user"`
	Contacts []string `json:"contacts"`
}

type Client struct {
	name       string
	serverURL  string
	privateKey []byte
	publicKey  []byte
	httpClient *http.Client
	printMu    sync.Mutex
}

func main() {
	serverURL := flag.String("server", getenv("METACHAT_SERVER", "http://localhost:8080"), "relay server URL")
	username := flag.String("user", "", "client username, for example john or smite")
	recipient := flag.String("to", "", "send one message to this user, then exit unless -listen is set")
	message := flag.String("message", "", "message text for one-shot sends")
	listen := flag.Bool("listen", false, "keep polling this user's mailbox")
	poll := flag.Duration("poll", 700*time.Millisecond, "mailbox polling interval")
	flag.Parse()

	name := strings.TrimSpace(*username)
	if name == "" {
		fmt.Println("[CLIENT] Missing -user. Example: go run ./client -user john")
		flag.Usage()
		os.Exit(2)
	}

	client := NewClient(name, *serverURL)
	if err := client.UploadPrekey(); err != nil {
		client.printf("[%s] Could not register with server: %v\n", client.name, err)
		os.Exit(1)
	}
	client.printf("[%s] Registered prekey with %s\n", client.name, client.serverURL)

	if strings.TrimSpace(*recipient) != "" {
		text := strings.TrimSpace(*message)
		if text == "" {
			text = strings.TrimSpace(strings.Join(flag.Args(), " "))
		}
		if text == "" {
			client.printf("[%s] Message is empty. Use -message or pass text after the flags.\n", client.name)
			os.Exit(2)
		}
		if err := client.Send(strings.TrimSpace(*recipient), text); err != nil {
			client.printf("[%s] Send failed: %v\n", client.name, err)
			os.Exit(1)
		}
		client.printf("[%s] Sent encrypted message to %s\n", client.name, strings.TrimSpace(*recipient))
		if !*listen {
			return
		}
	}

	if *listen {
		client.printf("[%s] Listening for encrypted messages. Press Ctrl+C to stop.\n", client.name)
		client.Listen(context.Background(), *poll)
		return
	}

	if err := client.RunInteractive(*poll); err != nil {
		client.printf("[%s] Client stopped: %v\n", client.name, err)
		os.Exit(1)
	}
}

func NewClient(name, serverURL string) *Client {
	privateKey, publicKey := crypto.GenerateKeyPair()
	return &Client{
		name:       name,
		serverURL:  strings.TrimRight(serverURL, "/"),
		privateKey: privateKey,
		publicKey:  publicKey,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *Client) UploadPrekey() error {
	data, err := json.Marshal(PrekeyBundle{IdentityKey: c.publicKey})
	if err != nil {
		return err
	}

	resp, err := c.httpClient.Post(c.endpoint("/upload_prekey", map[string]string{"user": c.name}), "application/json", bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return expectOK(resp, "upload prekey")
}

func (c *Client) Send(to, plaintext string) error {
	to = strings.TrimSpace(to)
	if to == "" {
		return errors.New("recipient is empty")
	}
	if to == c.name {
		return errors.New("choose a different recipient")
	}

	recipientKey, err := c.FetchPrekey(to)
	if err != nil {
		return err
	}

	ephemeralPrivate, ephemeralPublic := crypto.GenerateKeyPair()
	shared := crypto.DH(ephemeralPrivate, recipientKey)
	r := ratchet.NewRatchet(shared, recipientKey)
	messageKey := r.NextMessageKey()
	nonce, ciphertext := crypto.Encrypt(messageKey, []byte(plaintext))

	msg := SecureMessage{
		FromUser:     c.name,
		FromIdentity: c.publicKey,
		EphemeralKey: ephemeralPublic,
		Nonce:        nonce,
		Ciphertext:   ciphertext,
	}
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	resp, err := c.httpClient.Post(c.endpoint("/send_secure", map[string]string{"to": to}), "application/json", bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return expectOK(resp, "send secure message")
}

func (c *Client) FetchPrekey(user string) ([]byte, error) {
	resp, err := c.httpClient.Get(c.endpoint("/prekey", map[string]string{"user": strings.TrimSpace(user)}))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := expectOK(resp, "fetch prekey"); err != nil {
		return nil, err
	}

	var bundle PrekeyBundle
	if err := json.NewDecoder(resp.Body).Decode(&bundle); err != nil {
		return nil, err
	}
	if len(bundle.IdentityKey) != 32 {
		return nil, fmt.Errorf("invalid prekey length for %s: %d", user, len(bundle.IdentityKey))
	}
	return bundle.IdentityKey, nil
}

func (c *Client) FetchOne() (bool, error) {
	resp, err := c.httpClient.Get(c.endpoint("/fetch_secure", map[string]string{"user": c.name}))
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if err := expectOK(resp, "fetch secure message"); err != nil {
		return false, err
	}

	var msg SecureMessage
	if err := json.NewDecoder(resp.Body).Decode(&msg); err != nil {
		return false, err
	}
	if len(msg.Ciphertext) == 0 {
		return false, nil
	}
	if len(msg.EphemeralKey) != 32 || len(msg.Nonce) == 0 {
		return true, errors.New("received malformed encrypted message")
	}

	shared := crypto.DH(c.privateKey, msg.EphemeralKey)
	r := ratchet.NewRatchet(shared, msg.EphemeralKey)
	messageKey := r.NextMessageKey()
	plaintext, err := crypto.DecryptWithError(messageKey, msg.Nonce, msg.Ciphertext)
	if err != nil {
		from := msg.FromUser
		if from == "" {
			from = "unknown"
		}
		return true, fmt.Errorf("could not decrypt message from %s: %w", from, err)
	}

	from := msg.FromUser
	if from == "" {
		from = "unknown"
	}
	c.printf("\n[%s -> %s] %s\n", from, c.name, string(plaintext))
	return true, nil
}

func (c *Client) Connect(peer string) error {
	peer = strings.TrimSpace(peer)
	if peer == "" {
		return errors.New("peer is empty")
	}
	req, err := http.NewRequest(http.MethodPost, c.endpoint("/connect", map[string]string{"user": c.name, "peer": peer}), nil)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return expectOK(resp, "connect users")
}

func (c *Client) ListUsers() ([]string, error) {
	resp, err := c.httpClient.Get(c.endpoint("/users", nil))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := expectOK(resp, "list users"); err != nil {
		return nil, err
	}
	var users UsersResponse
	if err := json.NewDecoder(resp.Body).Decode(&users); err != nil {
		return nil, err
	}
	return users.Users, nil
}

func (c *Client) ListContacts() ([]string, error) {
	resp, err := c.httpClient.Get(c.endpoint("/contacts", map[string]string{"user": c.name}))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := expectOK(resp, "list contacts"); err != nil {
		return nil, err
	}
	var contacts ContactsResponse
	if err := json.NewDecoder(resp.Body).Decode(&contacts); err != nil {
		return nil, err
	}
	return contacts.Contacts, nil
}

func (c *Client) RunInteractive(poll time.Duration) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Listen(ctx, poll)

	c.printf("[%s] MetaChat ready. Use /help for commands.\n", c.name)
	selectedRecipient := ""
	scanner := bufio.NewScanner(os.Stdin)

	for {
		c.prompt(selectedRecipient)
		if !scanner.Scan() {
			return scanner.Err()
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "/") {
			quit, err := c.handleCommand(line, &selectedRecipient)
			if err != nil {
				c.printf("[%s] %v\n", c.name, err)
			}
			if quit {
				return nil
			}
			continue
		}

		if selectedRecipient == "" {
			c.printf("[%s] Choose a recipient with /to <user>, or send once with /send <user> <message>.\n", c.name)
			continue
		}
		if err := c.Send(selectedRecipient, line); err != nil {
			c.printf("[%s] Send failed: %v\n", c.name, err)
			continue
		}
		c.printf("[%s] Sent encrypted message to %s\n", c.name, selectedRecipient)
	}
}

func (c *Client) Listen(ctx context.Context, poll time.Duration) {
	if poll <= 0 {
		poll = 700 * time.Millisecond
	}
	ticker := time.NewTicker(poll)
	defer ticker.Stop()

	lastErr := ""
	for {
		_, err := c.FetchOne()
		if err != nil {
			msg := err.Error()
			if msg != lastErr {
				c.printf("[%s] Receive error: %v\n", c.name, err)
				lastErr = msg
			}
		} else {
			lastErr = ""
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (c *Client) handleCommand(line string, selectedRecipient *string) (bool, error) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return false, nil
	}

	switch fields[0] {
	case "/help":
		c.printHelp()
	case "/users":
		users, err := c.ListUsers()
		if err != nil {
			return false, err
		}
		c.printf("[%s] Users: %s\n", c.name, formatList(users))
	case "/contacts":
		contacts, err := c.ListContacts()
		if err != nil {
			return false, err
		}
		c.printf("[%s] Contacts: %s\n", c.name, formatList(contacts))
	case "/connect":
		if len(fields) < 2 {
			return false, errors.New("usage: /connect <user>")
		}
		if err := c.Connect(fields[1]); err != nil {
			return false, err
		}
		c.printf("[%s] Connected with %s\n", c.name, fields[1])
	case "/to":
		if len(fields) < 2 {
			return false, errors.New("usage: /to <user>")
		}
		*selectedRecipient = fields[1]
		c.printf("[%s] Active recipient is now %s\n", c.name, *selectedRecipient)
	case "/send":
		parts := strings.SplitN(line, " ", 3)
		if len(parts) < 3 || strings.TrimSpace(parts[2]) == "" {
			return false, errors.New("usage: /send <user> <message>")
		}
		to := strings.TrimSpace(parts[1])
		text := strings.TrimSpace(parts[2])
		if err := c.Send(to, text); err != nil {
			return false, err
		}
		c.printf("[%s] Sent encrypted message to %s\n", c.name, to)
	case "/quit", "/exit":
		return true, nil
	default:
		return false, fmt.Errorf("unknown command %q; use /help", fields[0])
	}

	return false, nil
}

func (c *Client) printHelp() {
	c.printf(`Commands:
  /users                    list registered users
  /contacts                 list your saved connections
  /connect <user>           save a bidirectional connection
  /to <user>                set the active recipient
  /send <user> <message>    send one encrypted message
  /quit                     exit
`)
}

func (c *Client) endpoint(path string, params map[string]string) string {
	u, err := url.Parse(c.serverURL + path)
	if err != nil {
		return c.serverURL + path
	}
	q := u.Query()
	for key, value := range params {
		q.Set(key, value)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func (c *Client) prompt(selectedRecipient string) {
	c.printMu.Lock()
	defer c.printMu.Unlock()
	if selectedRecipient == "" {
		fmt.Printf("[%s] > ", c.name)
		return
	}
	fmt.Printf("[%s -> %s] > ", c.name, selectedRecipient)
}

func (c *Client) printf(format string, args ...any) {
	c.printMu.Lock()
	defer c.printMu.Unlock()
	fmt.Printf(format, args...)
}

func expectOK(resp *http.Response, action string) error {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	message := strings.TrimSpace(string(body))
	if message == "" {
		message = resp.Status
	}
	return fmt.Errorf("%s failed: %s", action, message)
}

func formatList(values []string) string {
	if len(values) == 0 {
		return "(none)"
	}
	return strings.Join(values, ", ")
}

func getenv(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}
