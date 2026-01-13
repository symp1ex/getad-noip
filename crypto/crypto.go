package crypto

import (
	"errors"
	"log"

	"github.com/fernet/fernet-go"
)

var key *fernet.Key

func init() {
	const base64Key = "t_qxC_HN04Tiy1ish2P27ROYSJt_m7_FE2JT6gYngOM="
	err := Init(base64Key)
	if err != nil {
		// Если не удалось инициализировать крипто, лучше аварийно завершить программу
		log.Fatal("crypto init failed:", err)
	}
}

// Init — вызвать ОДИН РАЗ при старте сервера
func Init(base64Key string) error {
	k, err := fernet.DecodeKey(base64Key)
	if err != nil {
		return err
	}
	key = k
	return nil
}

// Encrypt — универсальное шифрование
func Encrypt(value string) (string, error) {
	if key == nil {
		return "", errors.New("crypto not initialized")
	}

	token, err := fernet.EncryptAndSign([]byte(value), key)
	if err != nil {
		return "", err
	}

	return string(token), nil
}

// Decrypt — универсальная дешифровка
func Decrypt(token string) (string, bool) {
	if key == nil || token == "" {
		return "", false
	}

	data := fernet.VerifyAndDecrypt(
		[]byte(token),
		0,
		[]*fernet.Key{key},
	)

	if data == nil {
		return "", false
	}

	return string(data), true
}

// Verify — сравнение plaintext с зашифрованным значением
func Verify(encrypted string, plain string) bool {
	value, ok := Decrypt(encrypted)
	if !ok {
		return false
	}
	return value == plain
}
