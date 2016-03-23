package oauth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/captncraig/caddy-util"
	"github.com/google/go-github/github"
	"github.com/mholt/caddy/caddy/setup"
	"github.com/mholt/caddy/middleware"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	ogh "golang.org/x/oauth2/github"
)

type module struct {
	next  middleware.Handler
	rules []*githubConfig
}

type githubConfig struct {
	enc  *encryptor
	conf *oauth2.Config

	Path string

	CookieName  string
	DefaultURL  string
	LoginURL    string
	CallbackURL string

	CookieSecret string
	ClientID     string
	ClientSecret string
	Scopes       string
	AllowedUsers []string
}

//encryptor with random key used to encrypt/decrypt oauth state cookies.
//only used within lifetime of this process.
var stateEncryptor *encryptor

func init() {
	dat := make([]byte, 64)
	rand.Read(dat)
	stateEncryptor = newEncryptor(string(dat))
}

func Setup(c *setup.Controller) (middleware.Middleware, error) {
	m := &module{}
	for c.Next() {
		conf := &githubConfig{}
		err := util.Unmarshal(c, conf)
		if err != nil {
			return nil, err
		}

		if conf.CookieSecret == "" {
			log.Println("Warning: No cookie secret provided for oauth block. Will use insecure default.")
			conf.CookieSecret = "zyxwqwertyuiop12345"
		}

		conf.enc = newEncryptor(conf.CookieSecret)
		conf.CookieSecret = ""

		if conf.Path == "" {
			conf.Path = "/"
		}

		if conf.LoginURL == "" {
			conf.LoginURL = "/login"
		}

		if conf.CallbackURL == "" {
			conf.CallbackURL = "/cb"
		}

		if conf.DefaultURL == "" {
			conf.DefaultURL = "/"
		}

		conf.conf = &oauth2.Config{
			Endpoint:     ogh.Endpoint,
			ClientID:     conf.ClientID,
			ClientSecret: conf.ClientSecret,
			Scopes:       strings.Split(conf.Scopes, ","),
		}

		m.rules = append(m.rules, conf)
	}
	return func(next middleware.Handler) middleware.Handler {
		m.next = next
		return m
	}, nil
}

//Clear any provider specific headers the user may have set by hand trying to be clever
func (g *githubConfig) ClearHeaders(r *http.Request) {
	r.Header.Del("X-GITHUB-USER")
	r.Header.Del("X-GITHUB-TOKEN")
	r.Header.Del("X-GITHUB-AVATAR")
}

type githubUser struct {
	Username string
	Token    string
	Avatar   string
}

func (g *githubConfig) GetCookieData(tok *oauth2.Token) (interface{}, error) {
	client := github.NewClient(oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(tok)))
	user, _, err := client.Users.Get("")
	if err != nil {
		return nil, fmt.Errorf("Unable to get user data from github.")
	}
	allowed := true
	if len(g.AllowedUsers) > 0 {
		allowed = false
		for _, u := range g.AllowedUsers {
			if u == *user.Login {
				allowed = true
				break
			}
		}
	}
	if !allowed {
		return nil, fmt.Errorf("User %s not allowed", *user.Login)
	}
	u := &githubUser{*user.Login, tok.AccessToken, *user.AvatarURL}
	return u, nil
}

//Read the cookie data. Set appropriate headers. If any problem with data return false.
//If successful, return true.
//If not authed, DO NOT set any downstream headers.
func (g *githubConfig) SetUserData(cookie string, r *http.Request) error {
	u := &githubUser{}
	if err := json.Unmarshal([]byte(cookie), u); err != nil {
		return fmt.Errorf("Error reading cookie")
	}
	r.Header.Set("X-GITHUB-USER", u.Username)
	r.Header.Set("X-GITHUB-TOKEN", u.Token)
	r.Header.Set("X-GITHUB-AVATAR", u.Avatar)
	return nil
}

func (m *module) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	path := middleware.Path(r.URL.Path)
	for _, rule := range m.rules {
		rule.ClearHeaders(r)

		//handle login
		if path.Matches(rule.LoginURL) {
			//TODO: state is short random string
			//store short lived cookie with name "encrypt(state)" and value of redirect uri
			http.Redirect(w, r, rule.conf.AuthCodeURL(""), 302)
			return 302, nil
		}

		//handle oauth callback
		if path.Matches(rule.CallbackURL) {
			//TODO: verify that user can produce the appropriate state cookie
			tok, err := rule.conf.Exchange(context.Background(), r.FormValue("code"))
			if err != nil {
				return rule.reject(w, r, "Exchange failed.")
			}
			data, err := rule.GetCookieData(tok)
			if err != nil {
				return rule.reject(w, r, err.Error())
			}
			rule.SetCookie(w, data)
			http.Redirect(w, r, rule.DefaultURL, 302)
			return 302, nil
		}

		// only check cookies if we match the root path
		if !path.Matches(rule.Path) {
			continue
		}
		authed := false
		// read existing cookie
		if cookie, err := r.Cookie(rule.CookieName); err == nil && cookie != nil {
			data := rule.enc.decrypt(cookie.Value)
			if data == "" {
				return rule.reject(w, r, "Invalid Cookie")
			}
			err = rule.SetUserData(data, r)
			if err != nil {
				return rule.reject(w, r, err.Error())
			} else {
				authed = true
			}
		}
		if !authed {
			return rule.reject(w, r, "")
		}
	}
	return m.next.ServeHTTP(w, r)
}

func (g *githubConfig) reject(w http.ResponseWriter, r *http.Request, msg string) (int, error) {
	data := struct{ LoginURL, Message string }{g.LoginURL, msg}
	w.WriteHeader(403)
	rejectTemplate.Execute(w, data)
	return 0, nil
}

func (g *githubConfig) SetCookie(w http.ResponseWriter, dat interface{}) {
	b, err := json.Marshal(dat)
	if err != nil {
		return
	}
	cookieVal := g.enc.encrypt(b)
	if cookieVal == "" {
		return
	}
	http.SetCookie(w, &http.Cookie{Name: g.CookieName, Secure: true, HttpOnly: true, Value: cookieVal, Path: "/", Expires: time.Now().Add(90 * 24 * time.Hour)})
}

func randString() string {
	data := make([]byte, 15)
	rand.Read(data)
	return base64.StdEncoding.EncodeToString(data)
}

func (g *githubConfig) SetStateCookie(w http.ResponseWriter, redirect string) (state string) {
	state = randString()
	encryptedState := g.enc.encrypt([]byte(state))
	cookieVal := g.enc.encrypt([]byte(redirect))
	http.SetCookie(w, &http.Cookie{Name: encryptedState, Secure: true, HttpOnly: true, Value: cookieVal, Path: "/", Expires: time.Now().Add(10 * time.Minute)})
	return
}
