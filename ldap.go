package hhuauth

import (
	"errors"
	"fmt"
	"github.com/go-ldap/ldap"
)

var (
	LDAPUnknownError = errors.New("unknown error")
	LDAPConnectionFailed = errors.New("connection failed")
	LDAPInvalidCredentials = errors.New("invalid credentials")
	LDAPNetworkError = errors.New("network error")
	LDAPUserNotFound = errors.New("user not found")
)

const (
	ldapUsernameFormat = "%s@ad.hhu.de"
	ldapFilterFormat   = "(sAMAccountName=%s)"
	ldapUrl            = "ldaps://ldaps.ad.hhu.de"
	ldapSearchBase     = "ou=IDMUsers,DC=AD,DC=hhu,DC=de"
	ldapId             = "sAMAccountName"
	ldapFirstName      = "givenName"
	ldapLastName       = "sn"
	ldapEmail          = "mail"
	ldapNoSizeLimit    = 0
	ldapNoTimeLimit    = 0
	ldapNoTypesOnly    = false
)

var (
	ldapDefaultAttributes = []string{ldapId, ldapFirstName, ldapLastName, ldapEmail}
)

type LDAPAuthenticator struct {}

func NewLDAPAutenticator() *LDAPAuthenticator {
	return &LDAPAuthenticator{}
}

func (auth *LDAPAuthenticator) Authenticate(username string, password string) (Student, error) {
	connection, err := ldap.DialURL(ldapUrl)
	if err != nil {
		return Student{}, LDAPConnectionFailed
	}

	defer connection.Close()

	ldapUsername := fmt.Sprintf(ldapUsernameFormat, username)

	err = connection.Bind(ldapUsername, password)
	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return Student{}, LDAPInvalidCredentials
		} else {
			return  Student{}, LDAPUnknownError
		}
	}

	searchRequest := newSearchRequest(username)
	searchResult, err := connection.Search(&searchRequest)
	if err != nil {
		return Student{}, LDAPNetworkError
	}

	if len(searchResult.Entries) == 0 {
		return Student{}, LDAPUserNotFound
	}

	return toStudent(searchResult), nil
}

func newSearchRequest(username string) ldap.SearchRequest {
	return ldap.SearchRequest{
		BaseDN: ldapSearchBase,
		Scope: ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		SizeLimit: ldapNoSizeLimit,
		TimeLimit: ldapNoTimeLimit,
		TypesOnly: ldapNoTypesOnly,
		Filter: fmt.Sprintf(ldapFilterFormat, username),
		Attributes: ldapDefaultAttributes,
		Controls: nil,
	}
}

func toStudent(result *ldap.SearchResult) Student {
	return Student{
		result.Entries[0].GetAttributeValue(ldapId),
		result.Entries[0].GetAttributeValue(ldapFirstName),
		result.Entries[0].GetAttributeValue(ldapLastName),
		result.Entries[0].GetAttributeValue(ldapEmail),
	}
}