package oauth

import (
	"fmt"
	"log"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/facebook"
	"github.com/markbates/goth/providers/github"
	"github.com/markbates/goth/providers/gplus"
	"github.com/mholt/caddy/caddy/setup"
	"github.com/mholt/caddy/middleware"
)

type oauthConfig struct {
	enc      *encryptor
	provider goth.Provider

	paths []string

	CookieName   string
	DefaultURL   string
	LoginURL     string
	LogoutURL    string
	CallbackURL  string
	AllowedUsers []string
	Provider     string
	RedirectHost string
}

type oauthModule struct {
	next  middleware.Handler
	rules []*oauthConfig
}

// Setup is the entrypoint for the middleware. Parses config and creates a handler
func Setup(c *setup.Controller) (middleware.Middleware, error) {
	m := &oauthModule{}
	for c.Next() {
		rule, err := parse(c)
		if err != nil {
			return nil, err
		}
		m.rules = append(m.rules, rule)
	}
	return func(next middleware.Handler) middleware.Handler {
		m.next = next
		return m
	}, nil
}

func parse(c *setup.Controller) (*oauthConfig, error) {
	rule := &oauthConfig{}
	// oauth /path /path2 type
	args := c.RemainingArgs()
	if len(args) < 1 {
		return nil, c.Err("Expect provider type as oauth parameter")
	}
	providerType := args[len(args)-1]
	rule.Provider = providerType
	constructor, ok := providerTypes[providerType]
	if !ok {
		return nil, c.Errf("Unknown oauth provider: %s", providerType)
	}
	rule.paths = args[:len(args)-1]

	//default operation paths
	rule.LoginURL = fmt.Sprintf("/auth/%s/login", providerType)
	rule.LogoutURL = fmt.Sprintf("/auth/%s/logout", providerType)
	rule.CallbackURL = fmt.Sprintf("/auth/%s/callback", providerType)
	rule.DefaultURL = "/"
	rule.CookieName = fmt.Sprintf("auth_%s", providerType)

	clientID, clientSecret, cookieSecret := "", "", ""
	var scopes []string

	for c.NextBlock() {
		var err error
		switch c.Val() {
		case "client_id":
			clientID, err = stringArg(c)
		case "client_secret":
			clientSecret, err = stringArg(c)
		case "scopes":
			scopes = c.RemainingArgs()
		case "login_url":
			rule.LoginURL, err = stringArg(c)
		case "callback_url":
			rule.CallbackURL, err = stringArg(c)
		case "cookie_name":
			rule.CookieName, err = stringArg(c)
		case "cookie_secret":
			cookieSecret, err = stringArg(c)
		case "allowed_users":
			rule.AllowedUsers = append(rule.AllowedUsers, c.RemainingArgs()...)
		case "path":
			rule.paths = append(rule.paths, c.RemainingArgs()...)
		case "redirect_host":
			rule.RedirectHost, err = stringArg(c)
		default:
			err = c.Errf("Unkown oauth config: %s", c.Val())
		}
		if err != nil {
			return nil, err
		}
	}

	if cookieSecret == "" {
		log.Println("WARNING: no cookie_secret specified. Will use insecure default.")
		cookieSecret = "cookies!!"
	}
	rule.enc = newEncryptor(cookieSecret)
	if clientID == "" || clientSecret == "" {
		return nil, c.Err("oauth requires client_id and client_secret")
	}
	redirectURI := rule.RedirectHost + rule.CallbackURL
	rule.provider = constructor(clientID, clientSecret, redirectURI, scopes...)
	return rule, nil
}

var providerTypes = map[string]func(string, string, string, ...string) goth.Provider{
	"github":   newGithub,
	"gplus":    newGoogle,
	"facebook": newFacebook,
}

func stringArg(c *setup.Controller) (string, error) {
	args := c.RemainingArgs()
	if len(args) != 1 {
		return "", c.ArgErr()
	}
	return args[0], nil
}

func newGithub(clientKey, secret, callbackURL string, scopes ...string) goth.Provider {
	return github.New(clientKey, secret, callbackURL, scopes...)
}

func newGoogle(clientKey, secret, callbackURL string, scopes ...string) goth.Provider {
	return gplus.New(clientKey, secret, callbackURL, scopes...)
}

func newFacebook(clientKey, secret, callbackURL string, scopes ...string) goth.Provider {
	return facebook.New(clientKey, secret, callbackURL, scopes...)
}
