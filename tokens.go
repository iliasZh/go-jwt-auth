package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type TokenPair struct {
	AccessToken  AccessToken  `json:"access_token"`
	RefreshToken RefreshToken `json:"refresh_token"`
}

// if error is nil, safe to refresh
func (tp *TokenPair) Refreshable() error {
	claims, err := tp.AccessToken.VerifyAndGetClaims()
	userUUID := claims.UserUUID

	// ignore expiration error for access token bc we're checking refreshability
	if e, ok := err.(*jwt.ValidationError); ok && (e.Errors == jwt.ValidationErrorExpired) {
		err = nil
	}

	if err != nil {
		return err
	}

	err = tp.RefreshToken.VerifyAgainst(&tp.AccessToken)

	if err != nil {
		return err
	}

	dbRecord, err := retrieveDatabaseRecord(userUUID)

	if err != nil {
		return err
	}

	return bcrypt.CompareHashAndPassword(dbRecord.RefreshTokenHash, []byte(tp.RefreshToken))
}

// JWT: header.payload.signature
type AccessToken string

func (token *AccessToken) getSignature() []byte {
	signatureBegin := strings.LastIndex(string(*token), ".") + 1
	return []byte((*token)[signatureBegin:])
}

func (token *AccessToken) String() string {
	return string(*token)
}

func (token *AccessToken) VerifyAndGetClaims() (*Claims, error) {
	keyfunc := func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(viperGetString("access_token_key")), nil
	}

	claims := &Claims{}
	_, err := jwt.ParseWithClaims(token.String(), claims, keyfunc)

	return claims, err
}

// this function does not validate!
func (token *AccessToken) getUserUUID() (uuid.UUID, error) {
	claims, err := token.VerifyAndGetClaims()

	// ignore validation errors
	if _, ok := err.(*jwt.ValidationError); ok {
		err = nil
	}
	return claims.UserUUID, err
}

// ---------------------------------------------

// custom: base64URL(expTime.signature)
// signature == HMAC-SHA512(expTime + accessToken.signature)
type RefreshToken string

func (token *RefreshToken) String() string {
	return string(*token)
}

func (token *RefreshToken) bcryptHash() ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(*token), bcrypt.DefaultCost)
}

func (token *RefreshToken) base64URLDecode() (string, error) {
	decodedByteArr, err := base64.URLEncoding.DecodeString(token.String())
	return string(decodedByteArr), err
}

func (token *RefreshToken) getExpirationDateAndSignature() ([]byte, []byte, error) {
	decodedToken, err := token.base64URLDecode()
	if err != nil {
		return nil, nil, err
	}

	dateAndSignature := strings.Split(decodedToken, ".")
	if len(dateAndSignature) != 2 {
		return nil, nil, errors.New("incorrect token format")
	}

	return []byte(dateAndSignature[0]), []byte(dateAndSignature[1]), err
}

func (token *RefreshToken) VerifyAgainst(accessToken *AccessToken) error {
	expTimeByteStr, signature, err := token.getExpirationDateAndSignature()
	if err != nil {
		return err
	}

	expectedSignature := generateRefreshTokenSignature(accessToken, expTimeByteStr)

	if !bytes.Equal(expectedSignature, signature) {
		return errors.New("invalid refresh token")
	}

	expTime, err := time.Parse(time.UnixDate, string(expTimeByteStr))

	if err != nil {
		return err
	}

	if !(expTime.After(time.Now())) {
		return errors.New("refresh token expired")
	}

	return nil
}
