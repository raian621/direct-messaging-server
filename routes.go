package main

import (
	"encoding/json"
	"log"
	"net/http"
)

func AttachHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/signup", handleSignUp)
	mux.HandleFunc("/signin", handleSignIn)
	mux.HandleFunc("/signout", handleSignOut)
}

func handleSignUp(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
	}

	var credentials struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	err := json.NewDecoder(r.Body).Decode(&credentials)
	if err != nil {
		log.Printf("Error decoding input: %v\n", err)
		w.WriteHeader(400)
		return
	}

	if len(credentials.Username) == 0 {
		log.Printf("user did not provide a username")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if len(credentials.Email) == 0 {
		log.Printf("user did not provide a email")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if len(credentials.Password) == 0 {
		log.Printf("user did not provide a password")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

}

func handleSignIn(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func handleSignOut(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
