// Package paseto provides a set of functions to handle the creation and
// verification of tokens using the PASETO library.
package paseto

import (
	"fmt"
	"time"

	"aidanwoods.dev/go-paseto"
)

// PasetoKeys is a struct that contains the private and public keys for signing
// and verifying tokens.
type PasetoKeys struct {
	PrivateKey paseto.V4AsymmetricSecretKey
	PublicKey  paseto.V4AsymmetricPublicKey
}

// InitializeKeys is a helper function to handle the initialization of the keys
// from strings for signing and verifying tokens.
//
// Arguments:
//   - privateHex: The private key in hex (string) format.
//   - publicHex: The public key in hex (string) format.
//
// Returns:
//   - The initialized keys.
//   - An error if the keys are invalid.
func InitializeKeys(privateHex string, publicHex string) (*PasetoKeys, error) {
	var err error

	privateKey, err := paseto.NewV4AsymmetricSecretKeyFromHex(privateHex)
	if err != nil {
		return nil, err
	}

	publicKey, err := paseto.NewV4AsymmetricPublicKeyFromHex(publicHex)
	if err != nil {
		return nil, err
	}

	return &PasetoKeys{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}, nil
}

// PasetoSign creates a token string with the given data inside the envelope
// and signs it with the given key and expiration time.
//
// Arguments:
//   - key: The secret key to use for signing the token.
//   - data: The data to sign.
//   - exp: The expiration time of the token.
//
// Returns:
//   - The signed token string.
func PasetoSign(secretKey paseto.V4AsymmetricSecretKey, data any, exp time.Time) string {
	token := paseto.NewToken()

	// Set the issued at time for downstream systems to determine if the token
	// is ready to be used depending on the system's policy.
	token.SetIssuedAt(time.Now())

	// Set the not before time for downstream systems to determine if the token
	// is ready to be used depending on the system's policy.
	token.SetNotBefore(time.Now())

	// Add the data object to the token envelope.
	token.Set("data", data)

	// Set when the token will expire (generally the most used field of tokens).
	token.SetExpiration(exp)

	return token.V4Sign(secretKey, nil)
}

// PasetoParse parses a token string if the signature is valid and was signed
// by the given key. If the signature is valid it returns the data using
// the generic type T.
//
// Arguments:
//   - key: The secret key to use for parsing the token.
//   - token: The token string to parse.
//
// Returns:
//   - The parsed data.
//   - An error if the token is invalid.
func PasetoParse[T any](secretKey paseto.V4AsymmetricSecretKey, token string) (T, error) {
	// Initialize the generic type T.
	var t T

	// Extract the public key from the secret key.
	publicKey := secretKey.Public()

	// Parse the token string using the public key.
	parser := paseto.NewParser()

	// Parse the token string using the public key.
	parsed, err := parser.ParseV4Public(publicKey, token, nil)
	if err != nil {
		return t, err
	}

	// Validate token expiration
	expiration, err := parsed.GetExpiration()
	if err != nil {
		return t, fmt.Errorf("failed to get expiration: %w", err)
	}
	if time.Now().After(expiration) {
		return t, fmt.Errorf("token has expired")
	}

	// Get the data from the parsed token.
	err = parsed.Get("data", &t)
	if err != nil {
		return t, err
	}

	return t, nil
}
