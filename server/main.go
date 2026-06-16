package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/redis/go-redis/v9"
)

var ctx = context.Background()
var rdb *redis.Client
var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

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

func main() {
	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "127.0.0.1:6379"
	}
	httpAddr := os.Getenv("HTTP_ADDR")
	if httpAddr == "" {
		httpAddr = ":8080"
	}

	rdb = redis.NewClient(&redis.Options{Addr: redisAddr})
	if err := rdb.Ping(ctx).Err(); err != nil {
		fmt.Println("[SERVER] Redis is not reachable at", redisAddr+":", err)
		os.Exit(1)
	}

	http.HandleFunc("/upload_prekey", uploadPrekey)
	http.HandleFunc("/prekey", getPrekey)
	http.HandleFunc("/users", listUsers)
	http.HandleFunc("/connect", connectUsers)
	http.HandleFunc("/contacts", listContacts)
	http.HandleFunc("/send_secure", sendSecure)
	http.HandleFunc("/fetch_secure", fetchSecure)

	fmt.Println("[SERVER] Running on", httpAddr, "(Redis:", redisAddr+")")
	if err := http.ListenAndServe(httpAddr, nil); err != nil {
		fmt.Println("[SERVER] HTTP server stopped:", err)
		os.Exit(1)
	}
}

func uploadPrekey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user, ok := userQuery(w, r, "user")
	if !ok {
		return
	}
	defer r.Body.Close()
	var bundle PrekeyBundle
	if err := json.NewDecoder(r.Body).Decode(&bundle); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("invalid JSON"))
		return
	}
	if len(bundle.IdentityKey) != 32 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("invalid identity_key length"))
		return
	}
	data, err := json.Marshal(bundle)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("marshal error"))
		return
	}
	pipe := rdb.TxPipeline()
	pipe.Set(ctx, "prekey:"+user, data, 0)
	pipe.SAdd(ctx, "users", user)
	if _, err := pipe.Exec(ctx); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("redis error"))
		return
	}
	fmt.Println("[SERVER] Stored prekey bundle for", user, "(Redis key: prekey:"+user+")")
	w.Write([]byte("OK"))
}

func getPrekey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user, ok := userQuery(w, r, "user")
	if !ok {
		return
	}
	val, err := rdb.Get(ctx, "prekey:"+user).Result()
	if err != nil {
		fmt.Println("[SERVER] Prekey not found for", user, "(Redis key: prekey:"+user+")")
		w.WriteHeader(404)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(val))
	fmt.Println("[SERVER] Served prekey bundle for", user)
}

func listUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	users, err := rdb.SMembers(ctx, "users").Result()
	if err != nil {
		http.Error(w, "redis error", http.StatusInternalServerError)
		return
	}
	sort.Strings(users)
	writeJSON(w, UsersResponse{Users: users})
}

func connectUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user, ok := userQuery(w, r, "user")
	if !ok {
		return
	}
	peer, ok := userQuery(w, r, "peer")
	if !ok {
		return
	}
	if user == peer {
		http.Error(w, "cannot connect a user to itself", http.StatusBadRequest)
		return
	}
	if !hasPrekey(user) || !hasPrekey(peer) {
		http.Error(w, "both users must upload prekeys before connecting", http.StatusNotFound)
		return
	}

	pipe := rdb.TxPipeline()
	pipe.SAdd(ctx, "contacts:"+user, peer)
	pipe.SAdd(ctx, "contacts:"+peer, user)
	if _, err := pipe.Exec(ctx); err != nil {
		http.Error(w, "redis error", http.StatusInternalServerError)
		return
	}
	fmt.Println("[SERVER] Established contact connection:", user, "<->", peer)
	w.Write([]byte("OK"))
}

func listContacts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user, ok := userQuery(w, r, "user")
	if !ok {
		return
	}

	contacts, err := rdb.SMembers(ctx, "contacts:"+user).Result()
	if err != nil {
		http.Error(w, "redis error", http.StatusInternalServerError)
		return
	}
	sort.Strings(contacts)
	writeJSON(w, ContactsResponse{User: user, Contacts: contacts})
}

func sendSecure(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	to, ok := userQuery(w, r, "to")
	if !ok {
		return
	}
	defer r.Body.Close()
	var msg SecureMessage
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("invalid JSON"))
		return
	}
	if len(msg.Ciphertext) == 0 || len(msg.Nonce) == 0 || len(msg.EphemeralKey) != 32 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("missing fields"))
		return
	}
	msg.FromUser = strings.TrimSpace(msg.FromUser)
	if msg.FromUser != "" && !validUsername(msg.FromUser) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("invalid from_user"))
		return
	}
	data, err := json.Marshal(msg)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("marshal error"))
		return
	}
	pipe := rdb.TxPipeline()
	pipe.LPush(ctx, "secure_mailbox:"+to, data)
	if msg.FromUser != "" {
		pipe.SAdd(ctx, "contacts:"+msg.FromUser, to)
		pipe.SAdd(ctx, "contacts:"+to, msg.FromUser)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("redis error"))
		return
	}
	fmt.Println("[SERVER] Queued secure message for", to, "(Redis list: secure_mailbox:"+to+")")
	w.Write([]byte("OK"))
}

func fetchSecure(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user, ok := userQuery(w, r, "user")
	if !ok {
		return
	}
	val, err := rdb.RPop(ctx, "secure_mailbox:"+user).Result()
	if err == redis.Nil {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("{}"))
		return
	}
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("redis error"))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(val))
	fmt.Println("[SERVER] Delivered 1 secure message to", user)
}

func userQuery(w http.ResponseWriter, r *http.Request, key string) (string, bool) {
	user := strings.TrimSpace(r.URL.Query().Get(key))
	if !validUsername(user) {
		http.Error(w, "invalid "+key+"; use 1-64 letters, numbers, dots, underscores, or hyphens", http.StatusBadRequest)
		return "", false
	}
	return user, true
}

func validUsername(user string) bool {
	return usernamePattern.MatchString(user)
}

func hasPrekey(user string) bool {
	n, err := rdb.Exists(ctx, "prekey:"+user).Result()
	return err == nil && n == 1
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		fmt.Println("[SERVER] Error writing JSON response:", err)
	}
}
