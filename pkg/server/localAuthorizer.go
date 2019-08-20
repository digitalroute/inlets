package server

import (
	"net/http"
)

type LocalAuthorizer struct {
	Token string
}

func (l *LocalAuthorizer) authorize(req *http.Request) bool {
	auth := req.Header.Get("Authorization")
	return len(l.Token) == 0 || auth == "Bearer "+l.Token
}
