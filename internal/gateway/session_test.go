package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestSessionSaveRoundTripAndSharedImmutableValue(t *testing.T) {
	session := testSession()
	var workers sync.WaitGroup
	failures := make(chan error, 4)
	for i := 0; i < 4; i++ {
		path := filepath.Join(t.TempDir(), ".session.json")
		workers.Add(1)
		go func() {
			defer workers.Done()
			for i := 0; i < 10; i++ {
				if err := session.Save(path); err != nil {
					failures <- err
					return
				}
				loaded, err := LoadSession(path)
				if err != nil {
					failures <- err
					return
				}
				if *loaded != *session {
					t.Error("cache replacement changed session contents")
					return
				}
			}
		}()
	}
	workers.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
}

func TestSessionSaveFailurePreservesExistingState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".session.json")
	if err := testSession().Save(path); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	invalid := testSession()
	invalid.Cookie = "SID=private-fixture; SID=duplicate"
	if err := invalid.Save(path); err == nil {
		t.Fatal("invalid replacement accepted")
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != string(original) {
		t.Fatalf("invalid replacement damaged original file: %v", err)
	}
	destinationDir := filepath.Join(dir, "directory")
	if err := os.Mkdir(destinationDir, 0700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(destinationDir, "keep")
	if err := os.WriteFile(marker, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := testSession().Save(destinationDir); err == nil {
		t.Fatal("session replacement overwrote a directory")
	}
	if data, err := os.ReadFile(marker); err != nil || string(data) != "original" {
		t.Fatalf("failed replacement damaged existing state: %v", err)
	}
	matches, err := filepath.Glob(filepath.Join(dir, ".session-write-*"))
	if err != nil || len(matches) != 0 {
		t.Fatal("session replacement leaked temporary files")
	}
	var session *Session
	if err := session.Save(filepath.Join(dir, "nil.json")); err == nil {
		t.Fatal("nil session persisted")
	}
}

func TestLoadSessionRejectsInvalidSchemasAndCookies(t *testing.T) {
	valid, err := json.Marshal(testSession())
	if err != nil {
		t.Fatal(err)
	}
	malformed := []string{
		"null", "{}", "[]", string(valid) + "{}", string(valid) + "private-fixture-token",
		strings.TrimSuffix(string(valid), "}") + `,"session_key":"private-fixture-key"}`,
		strings.Replace(string(valid), `"username":"alice"`, `"username":""`, 1),
		strings.Replace(string(valid), `"token":"private-fixture-token"`, `"token":""`, 1),
		strings.Replace(string(valid), `"cookie":"SID=fixture-session"`, `"cookie":"SID=first; other=second"`, 1),
		strings.Replace(string(valid), `"cookie":"SID=fixture-session"`, `"cookie":"SID=first; SID=second"`, 1),
		strings.Repeat("x", maxSessionSize+1),
	}
	path := filepath.Join(t.TempDir(), "session.json")
	for _, body := range malformed {
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		session, err := LoadSession(path)
		if err == nil || session != nil {
			t.Fatal("invalid cache accepted")
		}
		if strings.Contains(err.Error(), "private-fixture") {
			t.Fatal("cache error exposed a credential")
		}
	}
}

func TestSessionSchemaContainsOnlyGatewayCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	if err := testSession().Save(path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil || len(fields) != 5 {
		t.Fatal("gateway session retained unnecessary state")
	}
	for _, field := range []string{"username", "token", "user_id", "cookie", "created_at"} {
		if _, ok := fields[field]; !ok {
			t.Fatal("gateway session field missing")
		}
	}
}
