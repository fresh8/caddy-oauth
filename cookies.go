package oauth

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/markbates/goth"
)

//State Cookie stores raw random oauth state. The state we give to the provider is the hash of this.
//If the client has the corresponding cookie, we have confidence they are the original initiator.

func (o *oauthConfig) setStateCookie(state string, w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     o.stateCookieName(),
		Secure:   true,
		HttpOnly: true,
		Value:    state,
		Path:     "/",
		Expires:  time.Now().Add(10 * time.Minute),
	})
}

func (o *oauthConfig) clearCookie(name string, w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:    name,
		Value:   "",
		Path:    "/",
		Expires: time.Now().Add(-1 * time.Hour),
		MaxAge:  -10,
	})
}

func (o *oauthConfig) stateCookieName() string {
	return "oauth-state"
}

func (o *oauthConfig) stateCookieOk(w http.ResponseWriter, r *http.Request) bool {
	hash := r.FormValue("state")
	if hash == "" {
		return false
	}
	cookie, err := r.Cookie(o.stateCookieName())
	if err != nil || cookie == nil {
		return false
	}
	o.clearCookie(o.stateCookieName(), w)
	if hashState(cookie.Value) != hash {
		return false
	}
	return true
}

//Session Cookie is used to store the session between logn and callback. Not sure if necessary to persist, but goth recommends to.

func (o *oauthConfig) setSessionCookie(session goth.Session, w http.ResponseWriter) {
	dat := o.enc.encrypt([]byte(session.Marshal()))
	http.SetCookie(w, &http.Cookie{
		Name:     o.sessionCookieName(),
		Secure:   true,
		HttpOnly: true,
		Value:    dat,
		Path:     "/",
		Expires:  time.Now().Add(10 * time.Minute),
	})
}

func (o *oauthConfig) sessionCookieName() string {
	return "oauth-session"
}

func (o *oauthConfig) getSessionFromCookie(w http.ResponseWriter, r *http.Request) (goth.Session, error) {
	cookie, err := r.Cookie(o.sessionCookieName())
	if err != nil || cookie == nil {
		return nil, err
	}
	o.clearCookie(o.sessionCookieName(), w)
	dat := cookie.Value
	if dat == "" {
		return nil, fmt.Errorf("No session cookie present. Session timed out?")
	}
	dat = o.enc.decrypt(dat)
	if dat == "" {
		return nil, fmt.Errorf("Bad session cookie")
	}
	return o.provider.UnmarshalSession(dat)
}

// User Token has the full user data, json encoded, zipped, encrypted, and signed

func (o *oauthConfig) setUserCookie(u *goth.User, w http.ResponseWriter) error {
	buf := &bytes.Buffer{}
	gwriter := gzip.NewWriter(buf)
	encoder := json.NewEncoder(gwriter)
	u.RawData = nil
	if err := encoder.Encode(u); err != nil {
		return err
	}
	if err := gwriter.Flush(); err != nil {
		return err
	}
	cookieData := o.enc.encrypt(buf.Bytes())
	http.SetCookie(w, &http.Cookie{
		Name:     o.CookieName,
		Secure:   true,
		HttpOnly: true,
		Value:    cookieData,
		Path:     "/",
		Expires:  time.Now().Add(30 * 24 * time.Hour),
	})
	return nil
}

func (o *oauthConfig) getUserCookie(w http.ResponseWriter, r *http.Request) (*goth.User, error) {
	cookie, err := r.Cookie(o.CookieName)
	if err != nil || cookie == nil {
		return nil, nil
	}
	data := o.enc.decrypt(cookie.Value)
	if data == "" {
		o.clearCookie(o.CookieName, w)
		return nil, fmt.Errorf("Invalid user cookie")
	}
	unzipper, err := gzip.NewReader(strings.NewReader(data))
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(unzipper)
	user := &goth.User{}
	if err = decoder.Decode(user); err != nil {
		return nil, err
	}
	return user, nil
}
