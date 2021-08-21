package main

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
)

type Claims struct {
	UserUUID uuid.UUID `json:"user_uuid"`
	jwt.StandardClaims
}

func generateTokenPair(userUUID uuid.UUID) (TokenPair, error) {
	tokenPair := TokenPair{}

	claims := createPayload(&userUUID)

	var err error
	tokenPair.AccessToken, err = generateAccessToken(claims)
	if err != nil {
		return tokenPair, err
	}

	tokenPair.RefreshToken = generateRefreshToken(&tokenPair.AccessToken)
	return tokenPair, nil
}

func generateAccessToken(claims *Claims) (AccessToken, error) {
	// HMAC-SHA512 algorithm
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	jwtKey := []byte(viperGetString("access_token_key"))
	signedToken, err := token.SignedString(jwtKey)
	return AccessToken(signedToken), err
}

func generateRefreshToken(accessToken *AccessToken) RefreshToken {
	unencoded := generateUnencodedRefreshToken(accessToken)
	return RefreshToken(base64.URLEncoding.EncodeToString(unencoded))
}

// ---------------generateAccessToken helpers BEGIN---------------

func readUserUUIDFromQueryParams(r *http.Request) (uuid.UUID, error) {
	uuidStr := r.URL.Query().Get("user-uuid")
	return uuid.Parse(uuidStr)
}

func createPayload(userUUID *uuid.UUID) *Claims {
	timeToLiveInSeconds := viperGetInt("access_token_exp_seconds")
	timeToLive := time.Second * time.Duration(timeToLiveInSeconds)

	// Unix because gojwt expiration time is int64
	expirationTime := time.Now().Add(timeToLive).Unix()
	claims := &Claims{
		UserUUID: *userUUID,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime,
		},
	}
	return claims
}

// ---------------generateAccessToken helpers END---------------

// ---------------generateRefreshToken helpers BEGIN---------------

func generateUnencodedRefreshToken(accessToken *AccessToken) []byte {
	expTime := generateRefreshTokenExpirationTime()
	refreshToken := append(expTime, '.')

	signature := generateRefreshTokenSignature(accessToken, expTime)
	refreshToken = append(refreshToken, signature...)
	return refreshToken
}

func generateRefreshTokenSignature(accessToken *AccessToken, expTime []byte) []byte {
	key := []byte(viperGetString("refresh_token_key"))
	h := hmac.New(sha512.New, key)

	toSign := append(expTime, accessToken.getSignature()...)
	h.Write(toSign)
	return h.Sum(nil)
}

func generateRefreshTokenExpirationTime() []byte {
	timeToLiveInSeconds := viperGetInt("refresh_token_exp_seconds")
	timeToLive := time.Second * time.Duration(timeToLiveInSeconds)
	expTimeStr := time.Now().Add(timeToLive).Format(time.UnixDate)
	return []byte(expTimeStr)
}

// ---------------generateRefreshToken helpers END---------------
