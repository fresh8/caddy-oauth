package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/markbates/goth"
	"github.com/mholt/caddy/middleware"
)

func (m *oauthModule) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	//First, clear any of our headers that someone clever may have set. Don't let that nonsense downstream.
	for _, rule := range m.rules {
		rule.clearHeaders(r)
	}

	requestPath := middleware.Path(r.URL.Path)

	//Handle special login/callback endpoints
	for _, rule := range m.rules {
		if requestPath.Matches(rule.LoginURL) {
			return rule.handleLogin(w, r)
		}
		if requestPath.Matches(rule.CallbackURL) {
			return rule.handleCallback(w, r)
		}
		if requestPath.Matches(rule.LogoutURL) {
			rule.clearCookie(rule.CookieName, w)
			http.Redirect(w, r, rule.DefaultURL, http.StatusFound)
			return 0, nil
		}
	}

	//Every provider can decrypt cookies and set headers now
	for _, rule := range m.rules {
		u, err := rule.getUserCookie(w, r)
		if err != nil {
			fmt.Println(err, "BAD COOKIE")
			continue
		}
		if u == nil {
			continue
		}
		rule.setHeaders(r, u)
	}
	//Finally deny access if not authenticated to a protected path

	return m.next.ServeHTTP(w, r)
}

func (o *oauthConfig) clearHeaders(r *http.Request) {
	prefix := fmt.Sprintf("X-%s-", strings.ToUpper(o.Provider))
	for _, h := range []string{"USER", "TOKEN", "AVATAR"} {
		r.Header.Del(prefix + h)
	}
}

func (o *oauthConfig) setHeaders(r *http.Request, u *goth.User) {
	h := func(name string) string {
		return strings.ToUpper(fmt.Sprintf("X-%s-%s", o.provider.Name(), name))
	}
	r.Header.Set(h("USER"), u.NickName)
	r.Header.Set(h("AVATAR"), u.AvatarURL)
	r.Header.Set(h("TOKEN"), u.AccessToken)
}

func (o *oauthConfig) handleLogin(w http.ResponseWriter, r *http.Request) (int, error) {
	//make random state string. Store in short cookie
	state := randString()
	o.setStateCookie(state, w)
	//oauth state is hash of cookie state. Can't be reverse-engineered.
	state = hashState(state)
	session, err := o.provider.BeginAuth(state)
	if err != nil {
		return 500, err
	}
	url, err := session.GetAuthURL()
	if err != nil {
		return 500, err
	}
	//save session in cookie
	o.setSessionCookie(session, w)
	http.Redirect(w, r, url, http.StatusFound)
	return 0, nil
}

func (o *oauthConfig) handleCallback(w http.ResponseWriter, r *http.Request) (int, error) {
	// make sure this is the same user that started the session. They should have a state cookie
	if !o.stateCookieOk(w, r) {
		return 500, fmt.Errorf("Invalid state cookie")
	}
	// they should also have a session cookie. TODO: Is this really needed for all providers? I'm not sure if we can just create a new session or not
	session, err := o.getSessionFromCookie(w, r)
	if err != nil {
		return 500, err
	}
	_, err = session.Authorize(o.provider, r.URL.Query())
	if err != nil {
		return 500, err
	}
	user, err := o.provider.FetchUser(session)
	if err != nil {
		return 500, err
	}
	if err = o.setUserCookie(&user, w); err != nil {
		return 500, err
	}
	http.Redirect(w, r, o.DefaultURL, http.StatusFound)
	return 0, nil
}

func randString() string {
	data := make([]byte, 15)
	rand.Read(data)
	return base64.StdEncoding.EncodeToString(data)
}

func hashState(state string) string {
	b := sha256.Sum224([]byte(state))
	return base64.StdEncoding.EncodeToString(b[:])
}
