// Package jwt provides a set of functions to handle the creation and
// verification of tokens using the JWT library.
package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// JWTKeys is a struct that contains the private and public keys for signing
// and verifying tokens.
type JWTKeys struct {
	PrivateKey *ecdsa.PrivateKey
	PublicKey  *ecdsa.PublicKey
}

// CustomClaims is a struct that contains the custom claims for the token
// which you can use to add your own data to the envelope.
type CustomClaims[T any] struct {
	// The data is what is contained in the envelope.
	Data T `json:"data"`
	// The registered claims are the standard claims for the token that we
	// need to include in the envelope by embedding the RegisteredClaims struct.
	jwt.RegisteredClaims
}

// GenerateKeys generates a new ECDSA key pair for JWT signing and verification.
//
// Returns:
//   - The generated key pair.
//   - An error if key generation fails.
func GenerateKeys() (*JWTKeys, error) {
	curve := elliptic.P256()
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}

	return &JWTKeys{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	}, nil
}

// InitializeKeys initializes JWT keys from base64-encoded strings for signing
// and verifying tokens.
//
// Arguments:
//   - privateKeyBase64: The private key in base64 (string) format.
//   - publicKeyBase64: The public key in base64 (string) format.
//
// Returns:
//   - The initialized keys.
//   - An error if the keys are invalid.
func InitializeKeys(privateKeyBase64, publicKeyBase64 string) (*JWTKeys, error) {
	// Decode private key
	privateKeyDER, err := base64.URLEncoding.DecodeString(privateKeyBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %w", err)
	}

	privateKey, err := x509.ParseECPrivateKey(privateKeyDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	// Decode public key
	publicKeyDER, err := base64.URLEncoding.DecodeString(publicKeyBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}

	publicKeyInterface, err := x509.ParsePKIXPublicKey(publicKeyDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	publicKey, ok := publicKeyInterface.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("invalid public key type, expected ECDSA")
	}

	return &JWTKeys{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}, nil
}

// JWTSign creates a JWT token string with the given data inside the envelope
// and signs it with the given private key and expiration time.
//
// Arguments:
//   - privateKey: The private key to use for signing the token.
//   - data: The data to sign.
//   - exp: The expiration time of the token.
//
// Returns:
//   - The signed JWT token string.
//   - An error if signing fails.
func JWTSign[T any](privateKey *ecdsa.PrivateKey, data T, exp time.Time) (string, error) {
	now := time.Now()

	claims := CustomClaims[T]{
		Data: data,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(exp),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

// JWTParse parses a JWT token string if the signature is valid and was signed
// by the given public key. If the signature is valid it returns the data using
// the generic type T.
//
// Arguments:
//   - publicKey: The public key to use for verifying the token.
//   - tokenString: The JWT token string to parse.
//
// Returns:
//   - The parsed data.
//   - An error if the token is invalid.
func JWTParse[T any](publicKey *ecdsa.PublicKey, tokenString string) (T, error) {
	var result T

	claims := &CustomClaims[T]{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})

	if err != nil {
		return result, fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		return result, errors.New("token is not valid")
	}

	return claims.Data, nil
}

// SignCustomClaims signs the custom claims and returns the token string.
// The duration is the time the token will be valid for.
// The private key is the private key to sign the token with.
//
// Arguments:
//   - custom: The custom claims to sign.
//   - duration: The time the token will be valid for.
//   - privateKey: The private key to sign the token with.
//
// Returns:
//   - The token string.
//   - An error if the token could not be signed.
func SignCustomClaims[T any](custom T, duration time.Duration, privateKey *ecdsa.PrivateKey) (string, error) {
	exp := time.Now().Add(duration)
	return JWTSign(privateKey, custom, exp)
}

// ParseCustomClaims parses the token (validates) and returns the claims.
// The token string is the token to parse.
// The public key is the public key to verify the token with.
//
// Arguments:
//   - tokenString: The token to parse.
//   - publicKey: The public key to verify the token with.
//
// Returns:
//   - The claims.
//   - An error if the token could not be parsed.
func ParseCustomClaims[T any](tokenString string, publicKey *ecdsa.PublicKey) (*CustomClaims[T], error) {
	claims := &CustomClaims[T]{}
	_, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})

	if err != nil {
		return nil, err
	}

	return claims, nil
}
