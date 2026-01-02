package main

import (
	"encoding/json"
	"log"
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
	Error    string `json:"error,omitempty"`
}

type AuthState struct {
	Attempts int
	Blocked  time.Time
}

var (
	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}

	admins   = make(map[string]*Peer)
	clients  = make(map[string]*Peer)
	globalMu sync.Mutex

	passwords = map[string]string{}
	authState = map[string]*AuthState{}
	authMu    sync.Mutex
)

func loadPasswords() {
	data, err := os.ReadFile("passwords.json")
	if err != nil {
		log.Fatal("passwords.json not found")
	}
	json.Unmarshal(data, &passwords)
}

func savePasswords() {
	data, _ := json.MarshalIndent(passwords, "", "  ")
	_ = os.WriteFile("passwords.json", data, 0644)
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

		// ================= AUTH =================

		case "auth":
			authMu.Lock()
			state := authState[msg.ClientID]
			if state == nil {
				state = &AuthState{}
				authState[msg.ClientID] = state
			}

			if time.Now().Before(state.Blocked) {
				authMu.Unlock()
				conn.WriteJSON(Message{
					Type:  "auth_fail",
					Error: "Тайм-аут 1 минута",
				})
				continue
			}

			if passwords[msg.ClientID] != msg.Password {
				state.Attempts++
				if state.Attempts >= 3 {
					state.Blocked = time.Now().Add(time.Minute)
					state.Attempts = 0
				}
				authMu.Unlock()

				conn.WriteJSON(Message{
					Type:  "auth_fail",
					Error: "Неверный логин или пароль",
				})
				continue
			}

			state.Attempts = 0
			authMu.Unlock()

			authenticated = true
			conn.WriteJSON(Message{Type: "auth_ok"})

		// ================= REGISTER =================

		case "register":

			if msg.Role == "admin" && !authenticated {
				conn.WriteJSON(Message{
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

			authMu.Lock()
			stored, exists := passwords[msg.ID]

			if !exists {
				passwords[msg.ID] = msg.Password
				savePasswords()
				log.Println("New client registered:", msg.ID)
			} else if stored != msg.Password {
				authMu.Unlock()
				log.Println("Client auth failed:", msg.ID)
				return
			}

			authMu.Unlock()

			peer = &Peer{
				ID:   msg.ID,
				Role: "client",
				Conn: conn,
			}

			globalMu.Lock()
			clients[peer.ID] = peer
			globalMu.Unlock()

			log.Println("Client connected:", peer.ID)

			// === ATTACH ALL CURRENT ADMINS ===
			globalMu.Lock()
			for _, admin := range admins {
				_ = conn.WriteJSON(Message{
					Type: "admin_attach",
					ID:   admin.ID,
				})
			}
			globalMu.Unlock()

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
