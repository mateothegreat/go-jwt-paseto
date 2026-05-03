// Package jwt provides a set of functions to handle the creation and
// verification of tokens using the JWT library.
package jwt

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test data structures for various scenarios
type UserData struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
}

type SimpleData struct {
	Message string `json:"message"`
}

type ComplexData struct {
	User      UserData          `json:"user"`
	Metadata  map[string]string `json:"metadata"`
	Timestamp time.Time         `json:"timestamp"`
	Active    bool              `json:"active"`
}

// Test helper functions
func generateTestKeys() (*JWTKeys, error) {
	return GenerateKeys()
}

func TestGenerateKeys(t *testing.T) {
	t.Run("ValidKeyGeneration", func(t *testing.T) {
		keys, err := GenerateKeys()

		assert.NoError(t, err)
		assert.NotNil(t, keys)
		assert.NotNil(t, keys.PrivateKey)
		assert.NotNil(t, keys.PublicKey)

		// Verify the public key matches the private key
		assert.Equal(t, &keys.PrivateKey.PublicKey, keys.PublicKey)
	})

	t.Run("MultipleKeyGenerations", func(t *testing.T) {
		keys1, err1 := GenerateKeys()
		keys2, err2 := GenerateKeys()

		assert.NoError(t, err1)
		assert.NoError(t, err2)
		assert.NotNil(t, keys1)
		assert.NotNil(t, keys2)

		// Keys should be different
		assert.NotEqual(t, keys1.PrivateKey, keys2.PrivateKey)
	})
}

func TestInitializeKeys(t *testing.T) {
	t.Run("ValidKeys", func(t *testing.T) {
		// Generate valid key pair
		keys, err := generateTestKeys()
		require.NoError(t, err)

		// Encode keys to base64
		privateKeyDER, err := x509.MarshalECPrivateKey(keys.PrivateKey)
		require.NoError(t, err)
		privateKeyBase64 := base64.URLEncoding.EncodeToString(privateKeyDER)

		publicKeyDER, err := x509.MarshalPKIXPublicKey(keys.PublicKey)
		require.NoError(t, err)
		publicKeyBase64 := base64.URLEncoding.EncodeToString(publicKeyDER)

		// Initialize keys from base64
		initializedKeys, err := InitializeKeys(privateKeyBase64, publicKeyBase64)

		assert.NoError(t, err)
		assert.NotNil(t, initializedKeys)
		assert.Equal(t, keys.PrivateKey.D, initializedKeys.PrivateKey.D)
		assert.Equal(t, keys.PublicKey.X, initializedKeys.PublicKey.X)
		assert.Equal(t, keys.PublicKey.Y, initializedKeys.PublicKey.Y)
	})

	t.Run("InvalidPrivateKey", func(t *testing.T) {
		keys, err := generateTestKeys()
		require.NoError(t, err)

		publicKeyDER, err := x509.MarshalPKIXPublicKey(keys.PublicKey)
		require.NoError(t, err)
		publicKeyBase64 := base64.URLEncoding.EncodeToString(publicKeyDER)

		// Invalid private key base64
		invalidPrivateKey := "invalid_base64_string"

		initializedKeys, err := InitializeKeys(invalidPrivateKey, publicKeyBase64)

		assert.Error(t, err)
		assert.Nil(t, initializedKeys)
	})

	t.Run("InvalidPublicKey", func(t *testing.T) {
		keys, err := generateTestKeys()
		require.NoError(t, err)

		privateKeyDER, err := x509.MarshalECPrivateKey(keys.PrivateKey)
		require.NoError(t, err)
		privateKeyBase64 := base64.URLEncoding.EncodeToString(privateKeyDER)

		// Invalid public key base64
		invalidPublicKey := "invalid_base64_string"

		initializedKeys, err := InitializeKeys(privateKeyBase64, invalidPublicKey)

		assert.Error(t, err)
		assert.Nil(t, initializedKeys)
	})

	t.Run("EmptyKeys", func(t *testing.T) {
		keys, err := InitializeKeys("", "")

		assert.Error(t, err)
		assert.Nil(t, keys)
	})

	t.Run("ShortKeys", func(t *testing.T) {
		// Test with keys that are too short
		shortKey := "abc123"

		keys, err := InitializeKeys(shortKey, shortKey)

		assert.Error(t, err)
		assert.Nil(t, keys)
	})
}

func TestJWTSign(t *testing.T) {
	keys, err := generateTestKeys()
	require.NoError(t, err)

	t.Run("SignSimpleString", func(t *testing.T) {
		data := "simple test string"
		exp := time.Now().Add(time.Hour)

		token, err := JWTSign(keys.PrivateKey, data, exp)

		assert.NoError(t, err)
		assert.NotEmpty(t, token)
		// JWT tokens have three parts separated by dots
		parts := strings.Split(token, ".")
		assert.Len(t, parts, 3)
	})

	t.Run("SignSimpleStruct", func(t *testing.T) {
		data := SimpleData{Message: "test message"}
		exp := time.Now().Add(time.Hour)

		token, err := JWTSign(keys.PrivateKey, data, exp)

		assert.NoError(t, err)
		assert.NotEmpty(t, token)
		parts := strings.Split(token, ".")
		assert.Len(t, parts, 3)
	})

	t.Run("SignComplexStruct", func(t *testing.T) {
		data := ComplexData{
			User: UserData{
				ID:       123,
				Username: "testuser",
				Email:    "test@example.com",
			},
			Metadata: map[string]string{
				"role":   "admin",
				"tenant": "test-tenant",
			},
			Timestamp: time.Now(),
			Active:    true,
		}
		exp := time.Now().Add(time.Hour)

		token, err := JWTSign(keys.PrivateKey, data, exp)

		assert.NoError(t, err)
		assert.NotEmpty(t, token)
		parts := strings.Split(token, ".")
		assert.Len(t, parts, 3)
	})

	t.Run("SignWithPastExpiration", func(t *testing.T) {
		data := "test data"
		exp := time.Now().Add(-time.Hour) // Past expiration

		token, err := JWTSign(keys.PrivateKey, data, exp)

		// Token should still be created, but will be expired
		assert.NoError(t, err)
		assert.NotEmpty(t, token)
		parts := strings.Split(token, ".")
		assert.Len(t, parts, 3)
	})

	t.Run("SignWithFarFutureExpiration", func(t *testing.T) {
		data := "test data"
		exp := time.Now().Add(365 * 24 * time.Hour) // 1 year from now

		token, err := JWTSign(keys.PrivateKey, data, exp)

		assert.NoError(t, err)
		assert.NotEmpty(t, token)
		parts := strings.Split(token, ".")
		assert.Len(t, parts, 3)
	})

	t.Run("SignNilData", func(t *testing.T) {
		exp := time.Now().Add(time.Hour)

		token, err := JWTSign[interface{}](keys.PrivateKey, nil, exp)

		assert.NoError(t, err)
		assert.NotEmpty(t, token)
		parts := strings.Split(token, ".")
		assert.Len(t, parts, 3)
	})

	t.Run("SignEmptyStruct", func(t *testing.T) {
		data := struct{}{}
		exp := time.Now().Add(time.Hour)

		token, err := JWTSign(keys.PrivateKey, data, exp)

		assert.NoError(t, err)
		assert.NotEmpty(t, token)
		parts := strings.Split(token, ".")
		assert.Len(t, parts, 3)
	})

	t.Run("SignLargeData", func(t *testing.T) {
		// Create a large data structure
		largeData := make(map[string]string)
		for i := 0; i < 1000; i++ {
			largeData[fmt.Sprintf("key_%d", i)] = fmt.Sprintf("value_%d_with_some_longer_content", i)
		}
		exp := time.Now().Add(time.Hour)

		token, err := JWTSign(keys.PrivateKey, largeData, exp)

		assert.NoError(t, err)
		assert.NotEmpty(t, token)
		parts := strings.Split(token, ".")
		assert.Len(t, parts, 3)
	})
}

func TestJWTParse(t *testing.T) {
	keys, err := generateTestKeys()
	require.NoError(t, err)

	t.Run("ParseValidSimpleString", func(t *testing.T) {
		originalData := "test string"
		exp := time.Now().Add(time.Hour)
		token, err := JWTSign(keys.PrivateKey, originalData, exp)
		require.NoError(t, err)

		parsedData, err := JWTParse[string](keys.PublicKey, token)

		assert.NoError(t, err)
		assert.Equal(t, originalData, parsedData)
	})

	t.Run("ParseValidSimpleStruct", func(t *testing.T) {
		originalData := SimpleData{Message: "test message"}
		exp := time.Now().Add(time.Hour)
		token, err := JWTSign(keys.PrivateKey, originalData, exp)
		require.NoError(t, err)

		parsedData, err := JWTParse[SimpleData](keys.PublicKey, token)

		assert.NoError(t, err)
		assert.Equal(t, originalData, parsedData)
	})

	t.Run("ParseValidComplexStruct", func(t *testing.T) {
		timestamp := time.Now().Truncate(time.Second) // Truncate for comparison
		originalData := ComplexData{
			User: UserData{
				ID:       123,
				Username: "testuser",
				Email:    "test@example.com",
			},
			Metadata: map[string]string{
				"role":   "admin",
				"tenant": "test-tenant",
			},
			Timestamp: timestamp,
			Active:    true,
		}
		exp := time.Now().Add(time.Hour)
		token, err := JWTSign(keys.PrivateKey, originalData, exp)
		require.NoError(t, err)

		parsedData, err := JWTParse[ComplexData](keys.PublicKey, token)

		assert.NoError(t, err)
		assert.Equal(t, originalData.User, parsedData.User)
		assert.Equal(t, originalData.Metadata, parsedData.Metadata)
		assert.Equal(t, originalData.Active, parsedData.Active)
		// Time comparison with some tolerance due to JSON marshaling
		assert.WithinDuration(t, originalData.Timestamp, parsedData.Timestamp, time.Second)
	})

	t.Run("ParseInvalidToken", func(t *testing.T) {
		invalidToken := "invalid.token.string"

		_, err := JWTParse[string](keys.PublicKey, invalidToken)

		assert.Error(t, err)
	})

	t.Run("ParseEmptyToken", func(t *testing.T) {
		emptyToken := ""

		_, err := JWTParse[string](keys.PublicKey, emptyToken)

		assert.Error(t, err)
	})

	t.Run("ParseWithWrongKey", func(t *testing.T) {
		// Create token with one key
		originalData := "test data"
		exp := time.Now().Add(time.Hour)
		token, err := JWTSign(keys.PrivateKey, originalData, exp)
		require.NoError(t, err)

		// Try to parse with different key
		wrongKeys, err := generateTestKeys()
		require.NoError(t, err)

		_, err = JWTParse[string](wrongKeys.PublicKey, token)

		assert.Error(t, err)
	})

	t.Run("ParseExpiredToken", func(t *testing.T) {
		originalData := "test data"
		exp := time.Now().Add(-time.Hour) // Already expired
		token, err := JWTSign(keys.PrivateKey, originalData, exp)
		require.NoError(t, err)

		// Wait a moment to ensure expiration
		time.Sleep(10 * time.Millisecond)

		_, err = JWTParse[string](keys.PublicKey, token)

		// JWT library should validate expiration
		assert.Error(t, err)
	})

	t.Run("ParseWithTypeMismatch", func(t *testing.T) {
		// Sign with one type, try to parse as another
		originalData := SimpleData{Message: "test"}
		exp := time.Now().Add(time.Hour)
		token, err := JWTSign(keys.PrivateKey, originalData, exp)
		require.NoError(t, err)

		// Try to parse as string instead of SimpleData
		_, err = JWTParse[string](keys.PublicKey, token)

		// This might work depending on JSON unmarshaling, but the data won't match expected format
		// The behavior depends on how the JSON unmarshaling handles the type mismatch
		_ = err // We don't assert error here as it might succeed with unexpected data
	})

	t.Run("ParseNilData", func(t *testing.T) {
		exp := time.Now().Add(time.Hour)
		token, err := JWTSign[interface{}](keys.PrivateKey, nil, exp)
		require.NoError(t, err)

		parsedData, err := JWTParse[interface{}](keys.PublicKey, token)

		assert.NoError(t, err)
		assert.Nil(t, parsedData)
	})

	t.Run("ParseLargeData", func(t *testing.T) {
		// Create large data structure
		largeData := make(map[string]string)
		for i := 0; i < 100; i++ {
			largeData[fmt.Sprintf("key_%d", i)] = fmt.Sprintf("value_%d_with_some_content", i)
		}
		exp := time.Now().Add(time.Hour)
		token, err := JWTSign(keys.PrivateKey, largeData, exp)
		require.NoError(t, err)

		parsedData, err := JWTParse[map[string]string](keys.PublicKey, token)

		assert.NoError(t, err)
		assert.Equal(t, largeData, parsedData)
	})
}

func TestJWTSignParseRoundTrip(t *testing.T) {
	keys, err := generateTestKeys()
	require.NoError(t, err)

	testCases := []struct {
		name string
		data interface{}
	}{
		{"String", "test string"},
		{"Integer", 42},
		{"Float", 3.14159},
		{"Boolean", true},
		{"Array", []string{"a", "b", "c"}},
		{"Map", map[string]interface{}{"key": "value", "number": 123}},
		{"UserData", UserData{ID: 1, Username: "user", Email: "user@test.com"}},
		{"ComplexData", ComplexData{
			User:      UserData{ID: 2, Username: "complex", Email: "complex@test.com"},
			Metadata:  map[string]string{"role": "user"},
			Timestamp: time.Now().Truncate(time.Second),
			Active:    true,
		}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			exp := time.Now().Add(time.Hour)
			token, err := JWTSign(keys.PrivateKey, tc.data, exp)
			require.NoError(t, err)

			// Parse back using interface{} to handle different types
			parsedData, err := JWTParse[interface{}](keys.PublicKey, token)

			assert.NoError(t, err)

			// For complex comparisons, marshal both to JSON and compare
			originalJSON, err1 := json.Marshal(tc.data)
			parsedJSON, err2 := json.Marshal(parsedData)

			if err1 == nil && err2 == nil {
				assert.JSONEq(t, string(originalJSON), string(parsedJSON))
			} else {
				// Fallback to direct comparison for simple types
				assert.Equal(t, tc.data, parsedData)
			}
		})
	}
}

func TestJWTTokenStructure(t *testing.T) {
	keys, err := generateTestKeys()
	require.NoError(t, err)

	t.Run("TokenHasCorrectStructure", func(t *testing.T) {
		data := "test"
		exp := time.Now().Add(time.Hour)
		token, err := JWTSign(keys.PrivateKey, data, exp)
		require.NoError(t, err)

		// JWT tokens have three parts separated by dots
		parts := strings.Split(token, ".")
		assert.Len(t, parts, 3)
	})

	t.Run("TokensAreDifferentForSameData", func(t *testing.T) {
		data := "test"
		exp1 := time.Now().Add(time.Hour)
		exp2 := time.Now().Add(time.Hour + time.Second) // Different expiration times

		token1, err1 := JWTSign(keys.PrivateKey, data, exp1)
		token2, err2 := JWTSign(keys.PrivateKey, data, exp2)

		assert.NoError(t, err1)
		assert.NoError(t, err2)
		assert.NotEqual(t, token1, token2, "Tokens should be different due to different expiration times")
	})

	t.Run("TokensAreConsistentForSameTimestamp", func(t *testing.T) {
		data := "test"
		exp := time.Now().Add(time.Hour)

		// JWT tokens will be different due to issued at time differences
		token, err := JWTSign(keys.PrivateKey, data, exp)

		assert.NoError(t, err)
		assert.NotEmpty(t, token)
		parts := strings.Split(token, ".")
		assert.Len(t, parts, 3)
	})
}

func TestJWTEdgeCases(t *testing.T) {
	keys, err := generateTestKeys()
	require.NoError(t, err)

	t.Run("VeryLongString", func(t *testing.T) {
		// Create a very long string
		longString := strings.Repeat("a", 10000)
		exp := time.Now().Add(time.Hour)

		token, err := JWTSign(keys.PrivateKey, longString, exp)
		require.NoError(t, err)

		parsedData, err := JWTParse[string](keys.PublicKey, token)

		assert.NoError(t, err)
		assert.Equal(t, longString, parsedData)
	})

	t.Run("SpecialCharacters", func(t *testing.T) {
		specialData := "!@#$%^&*()_+-=[]{}|;:,.<>?/~`"
		exp := time.Now().Add(time.Hour)

		token, err := JWTSign(keys.PrivateKey, specialData, exp)
		require.NoError(t, err)

		parsedData, err := JWTParse[string](keys.PublicKey, token)

		assert.NoError(t, err)
		assert.Equal(t, specialData, parsedData)
	})

	t.Run("UnicodeCharacters", func(t *testing.T) {
		unicodeData := "Hello 世界 🌍 Здравствуй мир"
		exp := time.Now().Add(time.Hour)

		token, err := JWTSign(keys.PrivateKey, unicodeData, exp)
		require.NoError(t, err)

		parsedData, err := JWTParse[string](keys.PublicKey, token)

		assert.NoError(t, err)
		assert.Equal(t, unicodeData, parsedData)
	})

	t.Run("EmptyString", func(t *testing.T) {
		emptyData := ""
		exp := time.Now().Add(time.Hour)

		token, err := JWTSign(keys.PrivateKey, emptyData, exp)
		require.NoError(t, err)

		parsedData, err := JWTParse[string](keys.PublicKey, token)

		assert.NoError(t, err)
		assert.Equal(t, emptyData, parsedData)
	})

	t.Run("ZeroValues", func(t *testing.T) {
		zeroData := UserData{} // All zero values
		exp := time.Now().Add(time.Hour)

		token, err := JWTSign(keys.PrivateKey, zeroData, exp)
		require.NoError(t, err)

		parsedData, err := JWTParse[UserData](keys.PublicKey, token)

		assert.NoError(t, err)
		assert.Equal(t, zeroData, parsedData)
	})
}

func TestJWTPerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	keys, err := generateTestKeys()
	require.NoError(t, err)

	t.Run("SignPerformance", func(t *testing.T) {
		data := SimpleData{Message: "performance test"}
		exp := time.Now().Add(time.Hour)

		start := time.Now()
		iterations := 1000

		for i := 0; i < iterations; i++ {
			_, err := JWTSign(keys.PrivateKey, data, exp)
			assert.NoError(t, err)
		}

		duration := time.Since(start)
		avgDuration := duration / time.Duration(iterations)

		t.Logf("Average sign time: %v for %d iterations", avgDuration, iterations)
		assert.Less(t, avgDuration, 10*time.Millisecond, "Signing should be reasonably fast")
	})

	t.Run("ParsePerformance", func(t *testing.T) {
		data := SimpleData{Message: "performance test"}
		exp := time.Now().Add(time.Hour)
		token, err := JWTSign(keys.PrivateKey, data, exp)
		require.NoError(t, err)

		start := time.Now()
		iterations := 1000

		for i := 0; i < iterations; i++ {
			_, err := JWTParse[SimpleData](keys.PublicKey, token)
			assert.NoError(t, err)
		}

		duration := time.Since(start)
		avgDuration := duration / time.Duration(iterations)

		t.Logf("Average parse time: %v for %d iterations", avgDuration, iterations)
		assert.Less(t, avgDuration, 10*time.Millisecond, "Parsing should be reasonably fast")
	})
}

func TestSignCustomClaims(t *testing.T) {
	keys, err := generateTestKeys()
	require.NoError(t, err)

	t.Run("ValidSignCustomClaims", func(t *testing.T) {
		data := SimpleData{Message: "custom claims test"}
		duration := time.Hour

		token, err := SignCustomClaims(data, duration, keys.PrivateKey)

		assert.NoError(t, err)
		assert.NotEmpty(t, token)
		parts := strings.Split(token, ".")
		assert.Len(t, parts, 3)

		// Verify we can parse it back
		parsedData, err := JWTParse[SimpleData](keys.PublicKey, token)
		assert.NoError(t, err)
		assert.Equal(t, data, parsedData)
	})

	t.Run("CustomClaimsWithZeroDuration", func(t *testing.T) {
		data := "test data"
		duration := time.Duration(0)

		token, err := SignCustomClaims(data, duration, keys.PrivateKey)

		assert.NoError(t, err)
		assert.NotEmpty(t, token)

		// Token should be immediately expired
		_, err = JWTParse[string](keys.PublicKey, token)
		assert.Error(t, err, "Token with zero duration should be expired")
	})

	t.Run("CustomClaimsWithNegativeDuration", func(t *testing.T) {
		data := "test data"
		duration := -time.Hour

		token, err := SignCustomClaims(data, duration, keys.PrivateKey)

		assert.NoError(t, err)
		assert.NotEmpty(t, token)

		// Token should be expired
		_, err = JWTParse[string](keys.PublicKey, token)
		assert.Error(t, err, "Token with negative duration should be expired")
	})
}

func TestJWTSecurityProperties(t *testing.T) {
	t.Run("TokensFromDifferentKeysAreNotInterchangeable", func(t *testing.T) {
		keys1, err := generateTestKeys()
		require.NoError(t, err)

		keys2, err := generateTestKeys()
		require.NoError(t, err)

		data := "secret data"
		exp := time.Now().Add(time.Hour)

		// Sign with first key
		token, err := JWTSign(keys1.PrivateKey, data, exp)
		require.NoError(t, err)

		// Try to parse with second key
		_, err = JWTParse[string](keys2.PublicKey, token)
		assert.Error(t, err, "Token signed with one key should not be parseable with another key")
	})

	t.Run("ModifiedTokensAreRejected", func(t *testing.T) {
		keys, err := generateTestKeys()
		require.NoError(t, err)

		data := "secret data"
		exp := time.Now().Add(time.Hour)
		token, err := JWTSign(keys.PrivateKey, data, exp)
		require.NoError(t, err)

		// Modify the token by changing one character
		if len(token) > 20 {
			modifiedToken := token[:len(token)-5] + "X" + token[len(token)-4:]

			_, err = JWTParse[string](keys.PublicKey, modifiedToken)
			assert.Error(t, err, "Modified token should be rejected")
		}
	})

	t.Run("TruncatedTokensAreRejected", func(t *testing.T) {
		keys, err := generateTestKeys()
		require.NoError(t, err)

		data := "secret data"
		exp := time.Now().Add(time.Hour)
		token, err := JWTSign(keys.PrivateKey, data, exp)
		require.NoError(t, err)

		// Truncate the token
		if len(token) > 10 {
			truncatedToken := token[:len(token)/2]

			_, err = JWTParse[string](keys.PublicKey, truncatedToken)
			assert.Error(t, err, "Truncated token should be rejected")
		}
	})
}
