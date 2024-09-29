package main

import (
	"errors"
	"net/http"
)

var AuthError = errors.New("Unauthorized")

func Authorize(r *http.Request) error {
	username := r.FormValue("username")
	user, ok := users[username]
	if !ok {
		return AuthError
	}

	st, err := r.Cookie("session_token")
	if err != nil || st.Value == "" || st.Value != user.SessionToken {
		return AuthError
	}

	// CSRF token from the headers
	csrf := r.Header.Get("X-CSRF-Token")
	if csrf != user.CSRFToken || csrf == "" {
		return AuthError
	}
	
	return nil
}
