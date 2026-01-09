package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type Peer struct {
	ID   string
	Role string // "admin" or "client"
	Conn *websocket.Conn
	Mu   sync.Mutex
}

type Message struct {
	Type      string                 `json:"type"`
	ClientID  string                 `json:"client_id,omitempty"`
	CommandID string                 `json:"command_id,omitempty"`
	Command   string                 `json:"command,omitempty"`
	Prompt    string                 `json:"prompt,omitempty"`
	Result    map[string]interface{} `json:"result,omitempty"`
	Role      string                 `json:"role,omitempty"`
	ID        string                 `json:"id,omitempty"`

	// === AUTH ===
	Password string `json:"password,omitempty"`
	ApiKey   string `json:"api_key,omitempty"`
	TempPass string `json:"temp_pass,omitempty"`
	Error    string `json:"error,omitempty"`
}

type AuthState struct {
	Attempts int
	Blocked  time.Time
}

type PasswordEntry struct {
	TempPass string `json:"temp_pass"`
	Password any    `json:"password"` // всегда false
}

var (
	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}

	admins   = make(map[string]*Peer)
	clients  = make(map[string]*Peer)
	globalMu sync.Mutex

	passwords = make(map[string]*PasswordEntry)
	authState = make(map[string]*AuthState)
	authMu    sync.Mutex
)

func loadPasswords() {
	data, err := os.ReadFile("clients.json")
	if err != nil {
		passwords = make(map[string]*PasswordEntry)
		return
	}
	json.Unmarshal(data, &passwords)
}

func savePasswords() {
	data, _ := json.MarshalIndent(passwords, "", "  ")
	_ = os.WriteFile("clients.json", data, 0644)
}

func generateTempPass() string {
	rand.Seed(time.Now().UnixNano())
	return fmt.Sprintf("%05d", rand.Intn(100000))
}

func wsHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	var peer *Peer
	authenticated := false

	defer func() {
		// === ADMIN DETACH ON DISCONNECT ===
		if peer != nil && peer.Role == "admin" {
			globalMu.Lock()
			for _, client := range clients {
				_ = client.Conn.WriteJSON(Message{
					Type: "admin_detach",
					ID:   peer.ID,
				})
			}
			delete(admins, peer.ID)
			globalMu.Unlock()
			log.Println("Admin disconnected:", peer.ID)
		}

		if peer != nil && peer.Role == "client" {
			globalMu.Lock()

			for _, admin := range admins {
				admin.Mu.Lock()
				_ = admin.Conn.WriteJSON(Message{
					Type:     "session_closed",
					ClientID: peer.ID,
					Error:    "Client disconnected",
				})
				admin.Mu.Unlock()
			}

			delete(clients, peer.ID)
			globalMu.Unlock()

			log.Println("Client disconnected:", peer.ID)
		}

		conn.Close()
	}()

	for {
		var msg Message
		if err := conn.ReadJSON(&msg); err != nil {
			return
		}

		switch msg.Type {

		case "admin_hello":

			if msg.ApiKey != "123" {
				log.Println("Invalid admin api_key")
				_ = conn.WriteJSON(Message{
					Type:  "error",
					Error: "Invalid admin api_key",
				})
				return
			}

			// admin api_key валиден
			authenticated = true

			_ = conn.WriteJSON(Message{
				Type: "admin_hello_ok",
			})

		// ================= AUTH =================

		case "auth":

			authMu.Lock()
			entry, exists := passwords[msg.ClientID]

			if !exists {
				authMu.Unlock()
				conn.WriteJSON(Message{
					Type:  "auth_fail",
					Error: "Unknown client",
				})
				continue
			}

			ok := false

			if entry.Password != false && msg.Password == entry.Password {
				ok = true
			}

			if entry.TempPass != "" && msg.Password == entry.TempPass {
				ok = true
			}

			authMu.Unlock()

			if !ok {
				conn.WriteJSON(Message{
					Type:  "auth_fail",
					Error: "Invalid password",
				})
				continue
			}

			authenticated = true
			conn.WriteJSON(Message{Type: "auth_ok"})

		// ================= REGISTER =================

		case "register":

			if msg.Role == "admin" && !authenticated {
				_ = conn.WriteJSON(Message{
					Type:  "auth_fail",
					Error: "Admin not authenticated",
				})
				return
			}

			peer = &Peer{
				ID:   msg.ID,
				Role: msg.Role,
				Conn: conn,
			}

			globalMu.Lock()

			if peer.Role == "admin" {
				admins[peer.ID] = peer
				log.Println("Admin connected:", peer.ID)

				// === ADMIN ATTACH ===
				for _, client := range clients {
					_ = client.Conn.WriteJSON(Message{
						Type: "admin_attach",
						ID:   peer.ID,
					})
				}

			} else {
				clients[peer.ID] = peer
				log.Println("Client connected:", peer.ID)
			}

			globalMu.Unlock()

		// ================= CLIENT HELLO =================

		case "client_hello":

			if msg.ApiKey != "123" {
				log.Println("Invalid API key from client:", msg.ID)
				return
			}

			authMu.Lock()

			entry, exists := passwords[msg.ID]
			if !exists {
				entry = &PasswordEntry{
					Password: false,
				}
				passwords[msg.ID] = entry
			}

			// =========================
			// PASS-ONLY РЕЖИМ (-pass)
			// =========================
			if msg.Password != "" {
				entry.Password = msg.Password
				savePasswords()
				authMu.Unlock()

				log.Println("Password updated via pass-only connection:", msg.ID)
				return
			}

			// =========================
			// ОБЫЧНЫЙ PY-КЛИЕНТ
			// =========================

			entry.TempPass = generateTempPass()
			savePasswords()

			authMu.Unlock()

			peer = &Peer{
				ID:   msg.ID,
				Role: "client",
				Conn: conn,
			}

			globalMu.Lock()
			clients[peer.ID] = peer
			globalMu.Unlock()

			log.Println(
				"Client connected:",
				msg.ID,
				"temp_pass:", entry.TempPass,
				"password_set:", entry.Password != false,
			)

			// === ОТПРАВЛЯЕМ temp_pass PY-КЛИЕНТУ ===
			_ = conn.WriteJSON(Message{
				Type:     "temp_pass",
				TempPass: entry.TempPass,
			})

			// === ATTACH ADMINS ===
			for _, admin := range admins {
				_ = conn.WriteJSON(Message{
					Type: "admin_attach",
					ID:   admin.ID,
				})
			}

		// ================= ROUTING =================

		case "command", "interactive_response":
			globalMu.Lock()
			client := clients[msg.ClientID]
			globalMu.Unlock()

			if client != nil {
				client.Mu.Lock()
				_ = client.Conn.WriteJSON(Message{
					Type:      msg.Type,
					ClientID:  msg.ClientID,
					CommandID: msg.CommandID,
					Command:   msg.Command,
					ID:        msg.ID, // ← admin_id
				})
				client.Mu.Unlock()
			}

		case "interactive_prompt", "result":
			adminID := msg.ID

			globalMu.Lock()
			admin := admins[adminID]
			globalMu.Unlock()

			if admin != nil {
				admin.Mu.Lock()
				_ = admin.Conn.WriteJSON(msg)
				admin.Mu.Unlock()
			}

		case "session_closed":
			adminID := msg.ID

			globalMu.Lock()
			admin := admins[adminID]
			globalMu.Unlock()

			if admin != nil {
				admin.Mu.Lock()
				_ = admin.Conn.WriteJSON(Message{
					Type:  "session_closed",
					Error: "CMD session terminated on client",
				})
				admin.Mu.Unlock()
			}
		}
	}
}

func main() {
	loadPasswords()

	http.HandleFunc("/ws", wsHandler)
	log.Println("Server listening on :22233")
	http.ListenAndServe(":22233", nil)
}
