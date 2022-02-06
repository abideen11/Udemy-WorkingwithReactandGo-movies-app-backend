package main

import (
	"backend/models"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/pascaldekloe/jwt"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"time"
)

var validUser = models.User{
	ID:       10,
	Email:    "me@here.com",
	Password: "$2a$12$WYL96hYbQYA14cceflHix.T5CMVyGp2yLjks7DpA0pxzreif4n4O2",
}

type Credentials struct {
	Username string `json:"email"`
	Password string `json:"password"`
}

func (app *application) signIn(rw http.ResponseWriter, r *http.Request) {
	var creds Credentials

	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		app.errorJSON(rw, errors.New("unauthorized"))
		return
	}

	hashedPassword := validUser.Password

	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(creds.Password))
	if err != nil {
		app.errorJSON(rw, errors.New("unauthorized"))
		return
	}

	var claims jwt.Claims
	claims.Subject = fmt.Sprint(validUser.ID)
	claims.Issued = jwt.NewNumericTime(time.Now())
	claims.NotBefore = jwt.NewNumericTime(time.Now())
	claims.Expires = jwt.NewNumericTime(time.Now().Add(24 * time.Hour))
	claims.Issuer = "mydomain.com"
	claims.Audiences = []string{"mydomain.com"}

	jwtBytes, err := claims.HMACSign(jwt.HS256, []byte(app.config.jwt.secret))
	if err != nil {
		app.errorJSON(rw, errors.New("error signing"))
		return
	}

	app.writeJSON(rw, http.StatusOK, string(jwtBytes), "response")
}
