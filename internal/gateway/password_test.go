package gateway

import "testing"

func TestPasswordWireVectors(t *testing.T) {
	for _, tc := range []struct{ password, ciphertext string }{
		{"", "6WhJ/esGQYlsR8wydUZsmg=="},
		{"TestPass1234", "ZzG0DAgkkdLtBv7OIOrlDw=="},
		{"1234567890123456", "ElwPym5GHzGFIiNeP5c8b+qYVCxZBj9M/2XdnRc/BtI="},
		{"中文密码🔐", "Mm8/9ak4dEvefuz2WzXi0qVu1u0gL2zpdmmmP5Jvt28="},
	} {
		encrypted, err := encryptPassword(tc.password, "aQnaBtkLpMltNdei")
		if err != nil || encrypted != tc.ciphertext {
			t.Errorf("unexpected password wire encoding: %v", err)
		}
	}
}

func TestPasswordRejectsNonBlockKeys(t *testing.T) {
	for _, key := range []string{"", "short", "012345678901234567890123", "01234567890123456789012345678901"} {
		if _, err := encryptPassword("password", key); err == nil {
			t.Errorf("accepted %d-byte key", len(key))
		}
	}
}
