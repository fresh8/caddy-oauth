This is a middleware for [caddy](http://caddyserver.com) that provides authentication via github.

Once configured, the middleware will handle oauth authentication and cookie management. Your application will receive a set of cookies with the user's github
information if they are logged in.