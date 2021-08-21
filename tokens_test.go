package main

import (
	"reflect"
	"testing"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
)

func TestNewAccessTokenVerification(t *testing.T) {
	viperInit()
	tokenPair, err := generateTokenPair(uuid.New())
	if err != nil {
		t.Error("failed to generate the token pair")
	}

	_, err = tokenPair.AccessToken.VerifyAndGetClaims()
	if err != nil {
		t.Error("failed to verify newly generated access token")
	}
}

func TestExpiredAccessTokenVerification(t *testing.T) {
	viperInit()

	// sample expired access token
	accessToken := AccessToken(
		"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9." +
			"eyJ1c2VyX3V1aWQiOiIzYTY0MTQ3Yi1mZGFjLTRlOGItOTg2OS0wZmJiN2M0YzczN2IiLCJleHAiOjE2Mjk1NDIyNTd9." +
			"v-C3Z5Cl8f4Tte9Y6Xr2ptAQwba86lCmK_sYzH91vxWULmBavcA2AvjHSdImViPXUeZVrLUneg-5wtmCo1nPvg",
	)

	_, err := accessToken.VerifyAndGetClaims()

	e, ok := err.(*jwt.ValidationError)

	if !ok {
		t.Error("expected jwt.ValidationError, instead got ", reflect.TypeOf(err))
	}
	if e.Errors != jwt.ValidationErrorExpired {
		t.Error("expected only ValidationErrorExpired, instead got ", e.Errors)
	}
}

func TestTrashAppendedAccessTokenVerification(t *testing.T) {
	viperInit()

	// sample expired access token
	accessToken := AccessToken(
		"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9." +
			"eyJ1c2VyX3V1aWQiOiIzYTY0MTQ3Yi1mZGFjLTRlOGItOTg2OS0wZmJiN2M0YzczN2IiLCJleHAiOjE2Mjk1NDIyNTd9." +
			"v-C3Z5Cl8f4Tte9Y6Xr2ptAQwba86lCmK_sYzH91vxWULmBavcA2AvjHSdImViPXUeZVrLUneg-5wtmCo1nPvg" + // correct so far
			"blahblahblah", // some trash appended
	)

	_, err := accessToken.VerifyAndGetClaims()

	if err == nil {
		t.Error("error expected, got nil instead")
	}
}

func TestTrashAccessTokenVerification(t *testing.T) {
	viperInit()

	// sample expired access token
	accessToken := AccessToken(
		"halfkbdlfaglivbkuerfybdah",
	)

	_, err := accessToken.VerifyAndGetClaims()

	if err == nil {
		t.Error("error expected, got nil instead")
	}
}
