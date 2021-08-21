package main

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/google/uuid"
)

func homePage(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("<h1>Welcome to the home page</h1>"))
}

//	/get-tokens?user-uuid=<uuid>
func getTokens(w http.ResponseWriter, r *http.Request) {
	userUUID, err := readUserUUIDFromQueryParams(r)
	if err != nil {
		handleError("could not get user UUID from query", err, http.StatusBadRequest, w)
		return
	}

	issueTokenPair(w, userUUID)
}

//	/refresh-tokens
func refreshTokens(w http.ResponseWriter, r *http.Request) {
	tokenPair, err := readTokenPairFromRequest(r)
	if err != nil {
		handleError("failed to read the token pair from request", err, 0, w)
		return
	}

	if err = tokenPair.Refreshable(); err != nil {
		handleError("invalid token pair", err, http.StatusUnauthorized, w)
		return
	}

	userUUID, err := tokenPair.AccessToken.getUserUUID()
	if err != nil {
		handleError("invalid access token", err, http.StatusUnauthorized, w)
		return
	}

	issueTokenPair(w, userUUID)
}

func issueTokenPair(w http.ResponseWriter, userUUID uuid.UUID) {
	tokenPair, err := generateTokenPair(userUUID)
	if err != nil {
		handleError("failed to generate token pair", err, 0, w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(tokenPair)
	if err != nil {
		handleError("failed to encode the token pair to JSON", err, 0, w)
		return
	}

	err = registerRefreshTokenInDatabase(userUUID, tokenPair.RefreshToken)
	if err != nil {
		handleError("failed to put the refresh token to the database", err, 0, w)
		return
	}
}

func readTokenPairFromRequest(r *http.Request) (TokenPair, error) {
	headerContentType := r.Header.Get("Content-Type")
	if headerContentType != "application/json" {
		return TokenPair{}, errors.New("Content-Type is not application/json")
	}

	var tokenPair TokenPair
	err := json.NewDecoder(r.Body).Decode(&tokenPair)
	return tokenPair, err
}

// statusCode 0 == 500 Internal Server Error
func handleError(msg string, err error, statusCode int, w http.ResponseWriter) {
	if statusCode == 0 {
		statusCode = http.StatusInternalServerError
	}
	w.WriteHeader(statusCode)
	w.Write([]byte("Oops, there was an error, check the logs"))
	log.Println(msg+":", err)
}
