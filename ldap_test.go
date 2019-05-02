package hhuauth

import (
	"github.com/go-ldap/ldap"
	"strings"
	"testing"
)

const (
	testUser = "groot"
	testPassword = "iamgroot"
)

func TestLDAPAuthentication(t *testing.T) {
	authenticator := NewLDAPAutenticator()
	student, err := authenticator.Authenticate(testUser, testPassword)
	if err == nil {
		t.Fatal("test user should not be authenticated")
	}

	if !strings.Contains(err.Error(), ldap.LDAPResultCodeMap[ldap.LDAPResultInvalidCredentials]) {
		t.Fatal("server should respond with invalid credentials")
	}

	if len(student.Id) != 0 {
		t.Fatal("unauthenticated user should not contain any information")
	}
}