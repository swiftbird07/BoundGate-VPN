// boundgate-fakeidp is a throwaway OpenID Connect provider for the local
// lab: it logs a configured user in without asking. Development only.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/oidc/oidctest"
)

func main() {
	listen := flag.String("listen", ":9000", "listen address")
	issuer := flag.String("issuer", "http://idp:9000", "issuer URL as clients see it")
	clientID := flag.String("client-id", "boundgate", "OAuth client id")
	secret := flag.String("client-secret", "dev-secret", "OAuth client secret")
	user := flag.String("user", "martin", "subject and username of the user that is logged in")
	email := flag.String("email", "martin@example.test", "email claim")
	groups := flag.String("groups", "vpn-users,admins", "comma-separated groups claim")
	flag.Parse()
	p := oidctest.New(*issuer, *clientID, *secret, oidctest.User{Subject: *user, Username: *user, Email: *email, Groups: strings.Split(*groups, ",")})
	fmt.Fprintf(os.Stderr, "boundgate-fakeidp: issuer %s, client %s, user %s %v, listening on %s (DEVELOPMENT ONLY)\n", *issuer, *clientID, *user, strings.Split(*groups, ","), *listen)
	log.Fatal(http.ListenAndServe(*listen, p.Handler()))
}
