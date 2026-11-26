package guard

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// scramClient implements a pure-Go RFC 7677 SCRAM-SHA-256 client exchange
// shared by PostgreSQL 16 (AuthenticationSASL) and MongoDB 8.0 (saslStart/saslContinue).
type scramClient struct {
	username        string
	password        string
	clientNonce     string
	clientFirstBare string
	expectedSrvSig  []byte
}

func newSCRAMSHA256Client(username, password string) (*scramClient, error) {
	var nonceRaw [18]byte
	if _, err := rand.Read(nonceRaw[:]); err != nil {
		return nil, err
	}
	nonce := base64.StdEncoding.EncodeToString(nonceRaw[:])
	escapedUser := strings.ReplaceAll(strings.ReplaceAll(username, "=", "=3D"), ",", "=2C")
	return &scramClient{
		username:        username,
		password:        password,
		clientNonce:     nonce,
		clientFirstBare: fmt.Sprintf("n=%s,r=%s", escapedUser, nonce),
	}, nil
}

// ClientFirstMessage returns "n,,n=<user>,r=<nonce>".
func (s *scramClient) ClientFirstMessage() string {
	return "n,," + s.clientFirstBare
}

const maxSCRAMIterations = 1_000_000

// ProcessServerFirst parses the server's challenge "r=<fullNonce>,s=<b64Salt>,i=<iter>"
// and returns the client-final-message "c=biws,r=<fullNonce>,p=<b64Proof>".
func (s *scramClient) ProcessServerFirst(serverFirst string) (string, error) {
	var fullNonce, saltB64 string
	var iterations int
	for _, part := range strings.Split(serverFirst, ",") {
		if len(part) < 2 || part[1] != '=' {
			continue
		}
		switch part[0] {
		case 'r':
			fullNonce = part[2:]
		case 's':
			saltB64 = part[2:]
		case 'i':
			it, err := strconv.Atoi(part[2:])
			if err != nil {
				return "", fmt.Errorf("invalid scram iterations: %w", err)
			}
			iterations = it
		}
	}
	if !strings.HasPrefix(fullNonce, s.clientNonce) || saltB64 == "" || iterations <= 0 || iterations > maxSCRAMIterations {
		return "", errors.New("malformed SCRAM-SHA-256 server-first-message")
	}
	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		return "", fmt.Errorf("decode scram salt: %w", err)
	}

	saltedPassword := pbkdf2SHA256([]byte(s.password), salt, iterations, 32)
	clientKey := hmacSHA256(saltedPassword, []byte("Client Key"))
	storedKey := sha256.Sum256(clientKey)

	clientFinalWithoutProof := "c=biws,r=" + fullNonce
	authMessage := s.clientFirstBare + "," + serverFirst + "," + clientFinalWithoutProof

	clientSignature := hmacSHA256(storedKey[:], []byte(authMessage))
	clientProof := make([]byte, len(clientKey))
	for i := range clientKey {
		clientProof[i] = clientKey[i] ^ clientSignature[i]
	}

	serverKey := hmacSHA256(saltedPassword, []byte("Server Key"))
	s.expectedSrvSig = hmacSHA256(serverKey, []byte(authMessage))

	return clientFinalWithoutProof + ",p=" + base64.StdEncoding.EncodeToString(clientProof), nil
}

// VerifyServerFinal validates the server's "v=<b64Signature>" message.
func (s *scramClient) VerifyServerFinal(serverFinal string) error {
	for _, part := range strings.Split(serverFinal, ",") {
		if strings.HasPrefix(part, "v=") {
			got, err := base64.StdEncoding.DecodeString(part[2:])
			if err != nil {
				return err
			}
			if !hmac.Equal(got, s.expectedSrvSig) {
				return errors.New("SCRAM-SHA-256 server signature mismatch")
			}
			return nil
		}
		if strings.HasPrefix(part, "e=") {
			return fmt.Errorf("SCRAM server error: %s", part[2:])
		}
	}
	return errors.New("missing server signature in SCRAM server-final-message")
}

func hmacSHA256(key, msg []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	return mac.Sum(nil)
}

// pbkdf2SHA256 implements RFC 2898 PBKDF2 with HMAC-SHA256 using only Go stdlib.
func pbkdf2SHA256(password, salt []byte, iter, keyLen int) []byte {
	const hashLen = 32
	numBlocks := (keyLen + hashLen - 1) / hashLen
	out := make([]byte, 0, numBlocks*hashLen)
	var blockIdx [4]byte

	for block := 1; block <= numBlocks; block++ {
		blockIdx[0] = byte(block >> 24)
		blockIdx[1] = byte(block >> 16)
		blockIdx[2] = byte(block >> 8)
		blockIdx[3] = byte(block)

		mac := hmac.New(sha256.New, password)
		mac.Write(salt)
		mac.Write(blockIdx[:])
		u := mac.Sum(nil)
		t := append([]byte(nil), u...)

		for i := 1; i < iter; i++ {
			mac.Reset()
			mac.Write(u)
			u = mac.Sum(u[:0])
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}
