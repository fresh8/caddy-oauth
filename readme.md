This is a middleware for [caddy](http://caddyserver.com) that provides authentication via github.

Once configured, the middleware will handle oauth authentication and cookie management. Your application will receive a set of cookies with the user's github
information if they are logged in.

Example caddyfile:

```
:7777 {
  root testSite
  templates
  oauth {
    login_url /login
    callback_url /ghcb
    cookie_name gh_auth
    cookie_secret cookie-secret123
    client_id 2648712648716247814 
    client_secret 719824791827489124789
    scopes user:email
    allowed_users captncraig
    allowed_users mholt
  }
  errors visible
}

```