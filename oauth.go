package hhuauth

import (
	"context"
	"errors"
	"github.com/xanzy/go-gitlab"
	"golang.org/x/oauth2"
	"regexp"
	"strings"
)

var (
	OAuthInvalidUrl = errors.New("invalid base url")
	OAuthNoExternalIdentities = errors.New("no external identities")
	OAuthTokenExchangeFailed = errors.New("token exchange failed")
	OAuthUserAccessFailed = errors.New("accessing user api failed")
)

const (
	baseUrl = "https://git.hhu.de/api/v4"
)

var (
	regex = regexp.MustCompile(`cn=(?P<surname>[\w\s]+)\\,(?P<forename>[\w\s]+)\((?P<id>[\w\s]+)\)`)
)

type OAuthAuthenticator struct {
	config oauth2.Config
}

func NewOAuthAuthenticator(conf oauth2.Config) *OAuthAuthenticator {
	return &OAuthAuthenticator{conf}
}

func (auth *OAuthAuthenticator) GenerateAuthUrl(state string) string {
	return auth.config.AuthCodeURL(state, oauth2.AccessTypeOffline)
}


func (auth *OAuthAuthenticator) Authenticate(code string) (Student, error) {
	token, err := auth.config.Exchange(context.Background(), code)
	if err != nil {
		return Student{}, OAuthTokenExchangeFailed
	}

	client := gitlab.NewOAuthClient(nil, token.AccessToken)
	err = client.SetBaseURL(baseUrl)
	if err != nil {
		return Student{}, OAuthInvalidUrl
	}

	user, _, err := client.Users.CurrentUser()
	if err != nil {
		return Student{}, OAuthUserAccessFailed
	}

	if len(user.Identities) == 0 {
		return Student{}, OAuthNoExternalIdentities
	}

	match := regex.FindStringSubmatch(user.Identities[0].ExternUID)
	result := map[string]string{}
	for i, name := range regex.SubexpNames() {
		result[name] = strings.TrimSpace(match[i])
	}

	student := Student {
		Id: result["id"],
		Surname: strings.Title(result["surname"]),
		Forename: strings.Title(result["forename"]),
		Email: user.Email,
	}

	return student, nil
}
