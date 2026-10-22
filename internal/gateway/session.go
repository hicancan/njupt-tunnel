package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const maxSessionSize = 64 << 10

// Session is a gateway credential. Treat it as immutable after sharing;
// ValidateSession returns a replacement instead of mutating an active session.
// The transient password encryption key is never retained or persisted.
type Session struct {
	Username  string    `json:"username"`
	Token     string    `json:"token"`
	UserID    string    `json:"user_id"`
	Cookie    string    `json:"cookie"`
	CreatedAt time.Time `json:"created_at"`
}

func (s *Session) validate() error {
	if s == nil || strings.TrimSpace(s.Username) == "" || strings.TrimSpace(s.Token) == "" || strings.TrimSpace(s.UserID) == "" || s.CreatedAt.IsZero() {
		return errors.New("session has missing credential fields")
	}
	cookies := (&http.Request{Header: http.Header{"Cookie": {s.Cookie}}}).Cookies()
	if len(cookies) != 1 || cookies[0].Value == "" || cookies[0].Valid() != nil || cookies[0].String() != s.Cookie {
		return errors.New("session must contain one canonical session cookie")
	}
	return nil
}

// cookieName is only meaningful after validate has accepted the session.
func (s *Session) cookieName() string {
	name, _, _ := strings.Cut(s.Cookie, "=")
	return name
}

func (s *Session) Save(path string) error {
	if err := s.validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return errors.New("cannot encode session")
	}
	if len(data) > maxSessionSize {
		return errors.New("session is too large")
	}
	// A flushed sibling replaces the cache only after its complete write. Failed
	// login, encoding and filesystem operations preserve the last usable file.
	file, err := os.CreateTemp(filepath.Dir(path), ".session-write-*")
	if err != nil {
		return fmt.Errorf("create session replacement: %w", err)
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("write session replacement: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync session replacement: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close session replacement: %w", err)
	}
	if err := os.Rename(file.Name(), path); err != nil {
		return fmt.Errorf("replace session: %w", err)
	}
	return nil
}

func LoadSession(path string) (*Session, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read session: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxSessionSize+1))
	if err != nil {
		return nil, fmt.Errorf("read session: %w", err)
	}
	if len(data) > maxSessionSize {
		return nil, errors.New("session is too large")
	}
	var session Session
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&session) != nil || decoder.Decode(new(any)) != io.EOF {
		return nil, errors.New("invalid session JSON")
	}
	if err := session.validate(); err != nil {
		return nil, err
	}
	return &session, nil
}
