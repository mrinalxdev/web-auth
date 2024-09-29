package main

import (
	"fmt"
	"net/http"
	"time"
)

type Login struct {
	HashedPassword string
	SessionToken string
	CSRFToken string
}

var users = map[string]Login{}

func main(){
	http.HandleFunc("/register", register)
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", logout)
	http.HandleFunc("/protected", protected)
	http.ListenAndServe(":8080", nil)
	fmt.Println("The server is running")
}

func register(w http.ResponseWriter, r *http.Request){
	if r.Method != http.MethodPost {
		err := http.StatusMethodNotAllowed
		http.Error(w, "Invalid Method", err)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	if len(username) > 8 || len(password) > 8 {
		err := http.StatusNotAcceptable
		http.Error(w, "Invalid username/password", err)
		return
	}


	if _, ok := users[username]; ok {
		err := http.StatusConflict
		http.Error(w, "User already exist", err)
		return
	}

	hashedPassword, _ := hashPassword(password)
	users[username] = Login {
		HashedPassword : hashedPassword,
	}

	fmt.Fprintln(w, "User registered successfully !!")
}

func login(w http.ResponseWriter, r *http.Request){

	if r.Method != http.MethodPost {
		er := http.StatusMethodNotAllowed
		http.Error(w, "Invalid request method", er)
		return
	}
	
	username := r.FormValue("username")
	password := r.FormValue("password")

	user, ok := users[username]
	if !ok || !checkPasswordHash(password, user.HashedPassword) {
		er := http.StatusUnauthorized
		http.Error(w, "Invalid username or password", er)
		return
	}

	sessionToken := generateToken(32)
	csrfToken := generateToken(32) 

	// Set session cookie
	http.SetCookie(w, &http.Cookie{
		Name : "session_token",
		Value : sessionToken,
		Expires : time.Now().Add(24 * time.Hour),
		HttpOnly : true,
	})
	
	//Setting up CSRF token

	http.SetCookie(w, &http.Cookie{
		Name : "csrf_token",
		Value : csrfToken,
		Expires : time.Now().Add(24 * time.Hour),
		HttpOnly : false,
	})

	// Store tokens in the database
	user.SessionToken = sessionToken
	user.CSRFToken = csrfToken
	users[username] = user

	fmt.Fprintln(w, "Login Succesfull !")

}

func logout(w http.ResponseWriter, r *http.Request){
	if err := Authorize(r); err != nil {
		er := http.StatusUnauthorized
		http.Error(w, "Unauthorized", er)
		return
	}

	// Clearing the Caching
	http.SetCookie(w, &http.Cookie{
		Name: "session_token",
		Value: "",
		Expires: time.Now().Add(-time.Hour),
		HttpOnly: true,
	})

	http.SetCookie(w, &http.Cookie{
		Name : "csrf_token",
		Value : "",
		Expires : time.Now().Add(-time.Hour),
		HttpOnly : false,
	})


	//Clearing the tokens from the database
	username := r.FormValue("username")
	user, _ := users[username]
	user.SessionToken = ""
	user.CSRFToken = ""
	users[username] = user

	fmt.Fprintln(w, "Logged out successfully !!")
}

func protected(w http.ResponseWriter, r *http.Request){

	if r.Method != http.MethodPost {
		er := http.StatusMethodNotAllowed
		http.Error(w, "Invalid request method", er)
		return
	}

	if err := Authorize(r); err != nil {
		er := http.StatusUnauthorized
		http.Error(w, "Unauthorized", er)
		return
	}
	username := r.FormValue("username")
	fmt.Fprintf(w, "CSRF validation successful !! Welcome, %s", username)
}
