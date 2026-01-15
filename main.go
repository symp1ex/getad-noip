package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"posrelayd-noip/crypto"
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

	passwords    = make(map[string]*PasswordEntry)
	authStateMu  sync.Mutex
	authStateMap = make(map[string]*AuthState)
	authMu       sync.Mutex

	adminAttempts   = make(map[string]int)
	adminAttemptsMu sync.Mutex

	clientAttempts   = make(map[string]int)
	clientAttemptsMu sync.Mutex

	protocolViolations   = make(map[string]int)
	protocolViolationsMu sync.Mutex

	blacklist   = make(map[string]struct{})
	blacklistMu sync.Mutex
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

func loadBlacklist() {
	data, err := os.ReadFile("blacklist.txt")
	if err != nil {
		return
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			blacklist[line] = struct{}{}
		}
	}
}

// Добавляем IP в blacklist
func addToBlacklist(ip string) {
	blacklistMu.Lock()
	defer blacklistMu.Unlock()
	if _, exists := blacklist[ip]; exists {
		return
	}
	blacklist[ip] = struct{}{}
	f, _ := os.OpenFile("blacklist.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	defer f.Close()
	f.WriteString(ip + "\n")
}

func handleClientAuth(remoteIP string, msg Message, conn *websocket.Conn, entry *PasswordEntry) bool {
	authStateMu.Lock()
	state, exists := authStateMap[remoteIP]
	if !exists {
		state = &AuthState{}
		authStateMap[remoteIP] = state
	}
	authStateMu.Unlock()

	now := time.Now()
	if state.Blocked.After(now) {
		_ = conn.WriteJSON(Message{
			Type:  "auth_fail",
			Error: fmt.Sprintf("Too many failed attempts. Try again in %d seconds", int(state.Blocked.Sub(now).Seconds())),
		})
		return false
	}

	ok := false
	// === проверка паролей ===
	if entry.Password != false {
		if enc, ok2 := entry.Password.(string); ok2 && crypto.Verify(enc, msg.Password) {
			ok = true
		}
	}
	if entry.TempPass != "" && crypto.Verify(entry.TempPass, msg.Password) {
		ok = true
	}

	if !ok {
		// неудачная попытка
		authStateMu.Lock()
		state.Attempts++
		if state.Attempts >= 3 {
			state.Blocked = time.Now().Add(1 * time.Minute)
			state.Attempts = 0 // сбрасываем попытки после блокировки
			_ = conn.WriteJSON(Message{
				Type:  "auth_fail",
				Error: "Too many failed attempts. You are blocked for 1 minute",
			})
		} else {
			_ = conn.WriteJSON(Message{
				Type:  "auth_fail",
				Error: fmt.Sprintf("Invalid password (%d/3 attempts)", state.Attempts),
			})
		}
		authStateMu.Unlock()
		return false
	}

	// успешная авторизация → сброс состояния
	authStateMu.Lock()
	state.Attempts = 0
	state.Blocked = time.Time{}
	authStateMu.Unlock()

	_ = conn.WriteJSON(Message{Type: "auth_ok"})
	return true
}

func wsHandler(w http.ResponseWriter, r *http.Request) {
	remoteIP := strings.Split(r.RemoteAddr, ":")[0]

	// === ПРОВЕРКА BLACKLIST ДО UPGRADE ===
	blacklistMu.Lock()
	_, banned := blacklist[remoteIP]
	blacklistMu.Unlock()

	if banned {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("IP_BANNED"))
		return
	}

	// === ТОЛЬКО ТЕПЕРЬ UPGRADE ===
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

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

		if !authenticated {
			switch msg.Type {
			case "admin_hello", "auth", "client_hello":
				// разрешено
			default:
				protocolViolationsMu.Lock()
				protocolViolations[remoteIP]++
				attempts := protocolViolations[remoteIP]
				protocolViolationsMu.Unlock()

				log.Printf(
					"Protocol violation (unauthenticated) from %s: '%s' (%d/3)",
					remoteIP, msg.Type, attempts,
				)

				if attempts >= 3 {
					addToBlacklist(remoteIP)
					_ = conn.WriteJSON(Message{
						Type:  "error",
						Error: "Your IP is banned due to protocol violations",
					})
					return
				}

				_ = conn.WriteJSON(Message{
					Type:  "error",
					Error: "Authentication required",
				})
				continue
			}
		}

		if authenticated && peer == nil {
			switch msg.Type {
			case "register", "auth":
				// разрешено
			default:
				_ = conn.WriteJSON(Message{
					Type:  "error",
					Error: "Registration required",
				})
				continue
			}
		}

		switch msg.Type {
		case "admin_hello":
			if msg.ApiKey != "123" {
				adminAttemptsMu.Lock()
				adminAttempts[remoteIP]++
				attempts := adminAttempts[remoteIP]
				adminAttemptsMu.Unlock()

				if attempts >= 3 {
					addToBlacklist(remoteIP)
					_ = conn.WriteJSON(Message{
						Type:  "error",
						Error: "Your IP is banned due to too many failed attempts",
					})
					return
				}

				_ = conn.WriteJSON(Message{
					Type:  "error",
					Error: fmt.Sprintf("Invalid API key (%d/3 attempts)", attempts),
				})
				continue
			}

			// успешная авторизация → сброс счетчика
			adminAttemptsMu.Lock()
			delete(adminAttempts, remoteIP)
			adminAttemptsMu.Unlock()

			protocolViolationsMu.Lock()
			delete(protocolViolations, remoteIP)
			protocolViolationsMu.Unlock()

			authenticated = true
			_ = conn.WriteJSON(Message{
				Type: "admin_hello_ok",
			})

		// ================= AUTH =================

		case "auth":
			authMu.Lock()
			entry, exists := passwords[msg.ClientID]
			authMu.Unlock()

			if !exists {
				_ = conn.WriteJSON(Message{
					Type:  "auth_fail",
					Error: "Unknown client",
				})
				continue
			}

			globalMu.Lock()
			client, online := clients[msg.ClientID]
			globalMu.Unlock()

			if !online || client == nil {
				_ = conn.WriteJSON(Message{
					Type:  "auth_fail",
					Error: "Client is offline",
				})
				continue
			}

			if !handleClientAuth(remoteIP, msg, conn, entry) {
				continue
			}

			authenticated = true

			protocolViolationsMu.Lock()
			delete(protocolViolations, remoteIP)
			protocolViolationsMu.Unlock()

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
				clientAttemptsMu.Lock()
				clientAttempts[remoteIP]++
				attempts := clientAttempts[remoteIP]
				clientAttemptsMu.Unlock()

				log.Printf(
					"Invalid API key from client %s (%d/3)",
					remoteIP, attempts,
				)

				if attempts >= 3 {
					addToBlacklist(remoteIP)
					_ = conn.WriteJSON(Message{
						Type:  "error",
						Error: "Your IP is banned due to too many failed API key attempts",
					})
					return
				}

				_ = conn.WriteJSON(Message{
					Type:  "error",
					Error: fmt.Sprintf("Invalid API key (%d/3 attempts)", attempts),
				})
				continue
			}

			// успешный api_key → сброс счётчиков
			clientAttemptsMu.Lock()
			delete(clientAttempts, remoteIP)
			clientAttemptsMu.Unlock()

			protocolViolationsMu.Lock()
			delete(protocolViolations, remoteIP)
			protocolViolationsMu.Unlock()

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
				encrypted, err := crypto.Encrypt(msg.Password)
				if err != nil {
					authMu.Unlock()
					_ = conn.WriteJSON(Message{
						Type:  "error",
						Error: "Password encryption failed",
					})
					return
				}

				entry.Password = encrypted
				savePasswords()
				authMu.Unlock()

				log.Println("Password updated via pass-only connection:", msg.ID)

				_ = conn.WriteJSON(Message{
					Type: "password_updated",
				})

				_ = conn.WriteMessage(
					websocket.CloseMessage,
					websocket.FormatCloseMessage(websocket.CloseNormalClosure, "password updated"),
				)
				return
			}

			// =========================
			// ОБЫЧНЫЙ PY-КЛИЕНТ
			// =========================

			plainTemp := generateTempPass()

			encryptedTemp, err := crypto.Encrypt(plainTemp)
			if err != nil {
				authMu.Unlock()
				_ = conn.WriteJSON(Message{
					Type:  "error",
					Error: "Temp password encryption failed",
				})
				return
			}

			entry.TempPass = encryptedTemp
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
				TempPass: plainTemp,
			})

			authenticated = true

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

		default:
			protocolViolationsMu.Lock()
			protocolViolations[remoteIP]++
			attempts := protocolViolations[remoteIP]
			protocolViolationsMu.Unlock()

			log.Printf(
				"Protocol violation from %s: unknown message type '%s' (%d/3)",
				remoteIP, msg.Type, attempts,
			)

			if attempts >= 3 {
				addToBlacklist(remoteIP)

				_ = conn.WriteJSON(Message{
					Type:  "error",
					Error: "Your IP is banned due to protocol violations",
				})

				return
			}

			_ = conn.WriteJSON(Message{
				Type: "error",
				Error: fmt.Sprintf(
					"Unknown request type '%s' (%d/3)",
					msg.Type, attempts,
				),
			})
		}
	}
}

func main() {
	loadPasswords()
	loadBlacklist()

	http.HandleFunc("/ws", wsHandler)
	log.Println("Server listening on :22233")
	http.ListenAndServe(":22233", nil)
}
