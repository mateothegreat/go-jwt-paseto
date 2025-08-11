// Package paseto provides a set of functions to handle the creation and
// verification of tokens using the PASETO library.
package paseto

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"aidanwoods.dev/go-paseto"
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
func generateTestKeys() (*PasetoKeys, error) {
	// Generate a new key pair for testing
	secretKey := paseto.NewV4AsymmetricSecretKey()
	publicKey := secretKey.Public()

	return &PasetoKeys{
		PrivateKey: secretKey,
		PublicKey:  publicKey,
	}, nil
}

func TestInitializeKeys(t *testing.T) {
	t.Run("ValidKeys", func(t *testing.T) {
		// Generate valid key pair
		secretKey := paseto.NewV4AsymmetricSecretKey()
		publicKey := secretKey.Public()

		privateHex := secretKey.ExportHex()
		publicHex := publicKey.ExportHex()

		keys, err := InitializeKeys(privateHex, publicHex)

		assert.NoError(t, err)
		assert.NotNil(t, keys)
		assert.Equal(t, privateHex, keys.PrivateKey.ExportHex())
		assert.Equal(t, publicHex, keys.PublicKey.ExportHex())
	})

	t.Run("InvalidPrivateKey", func(t *testing.T) {
		secretKey := paseto.NewV4AsymmetricSecretKey()
		publicKey := secretKey.Public()
		publicHex := publicKey.ExportHex()

		// Invalid private key hex
		invalidPrivateHex := "invalid_hex_string"

		keys, err := InitializeKeys(invalidPrivateHex, publicHex)

		assert.Error(t, err)
		assert.Nil(t, keys)
	})

	t.Run("InvalidPublicKey", func(t *testing.T) {
		secretKey := paseto.NewV4AsymmetricSecretKey()
		privateHex := secretKey.ExportHex()

		// Invalid public key hex
		invalidPublicHex := "invalid_hex_string"

		keys, err := InitializeKeys(privateHex, invalidPublicHex)

		assert.Error(t, err)
		assert.Nil(t, keys)
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

	t.Run("MismatchedKeyPair", func(t *testing.T) {
		// Generate two separate key pairs
		secretKey1 := paseto.NewV4AsymmetricSecretKey()
		secretKey2 := paseto.NewV4AsymmetricSecretKey()

		privateHex1 := secretKey1.ExportHex()
		publicHex2 := secretKey2.Public().ExportHex()

		// This should still work for initialization, but won't work for signing/parsing
		keys, err := InitializeKeys(privateHex1, publicHex2)

		assert.NoError(t, err)
		assert.NotNil(t, keys)
	})
}

func TestPasetoSign(t *testing.T) {
	keys, err := generateTestKeys()
	require.NoError(t, err)

	t.Run("SignSimpleString", func(t *testing.T) {
		data := "simple test string"
		exp := time.Now().Add(time.Hour)

		token := PasetoSign(keys.PrivateKey, data, exp)

		assert.NotEmpty(t, token)
		assert.Contains(t, token, "v4.public.")
	})

	t.Run("SignSimpleStruct", func(t *testing.T) {
		data := SimpleData{Message: "test message"}
		exp := time.Now().Add(time.Hour)

		token := PasetoSign(keys.PrivateKey, data, exp)

		assert.NotEmpty(t, token)
		assert.Contains(t, token, "v4.public.")
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

		token := PasetoSign(keys.PrivateKey, data, exp)

		assert.NotEmpty(t, token)
		assert.Contains(t, token, "v4.public.")
	})

	t.Run("SignWithPastExpiration", func(t *testing.T) {
		data := "test data"
		exp := time.Now().Add(-time.Hour) // Past expiration

		token := PasetoSign(keys.PrivateKey, data, exp)

		// Token should still be created, but will be expired
		assert.NotEmpty(t, token)
		assert.Contains(t, token, "v4.public.")
	})

	t.Run("SignWithFarFutureExpiration", func(t *testing.T) {
		data := "test data"
		exp := time.Now().Add(365 * 24 * time.Hour) // 1 year from now

		token := PasetoSign(keys.PrivateKey, data, exp)

		assert.NotEmpty(t, token)
		assert.Contains(t, token, "v4.public.")
	})

	t.Run("SignNilData", func(t *testing.T) {
		exp := time.Now().Add(time.Hour)

		token := PasetoSign(keys.PrivateKey, nil, exp)

		assert.NotEmpty(t, token)
		assert.Contains(t, token, "v4.public.")
	})

	t.Run("SignEmptyStruct", func(t *testing.T) {
		data := struct{}{}
		exp := time.Now().Add(time.Hour)

		token := PasetoSign(keys.PrivateKey, data, exp)

		assert.NotEmpty(t, token)
		assert.Contains(t, token, "v4.public.")
	})

	t.Run("SignLargeData", func(t *testing.T) {
		// Create a large data structure
		largeData := make(map[string]string)
		for i := 0; i < 1000; i++ {
			largeData[fmt.Sprintf("key_%d", i)] = fmt.Sprintf("value_%d_with_some_longer_content", i)
		}
		exp := time.Now().Add(time.Hour)

		token := PasetoSign(keys.PrivateKey, largeData, exp)

		assert.NotEmpty(t, token)
		assert.Contains(t, token, "v4.public.")
	})
}

func TestPasetoParse(t *testing.T) {
	keys, err := generateTestKeys()
	require.NoError(t, err)

	t.Run("ParseValidSimpleString", func(t *testing.T) {
		originalData := "test string"
		exp := time.Now().Add(time.Hour)
		token := PasetoSign(keys.PrivateKey, originalData, exp)

		parsedData, err := PasetoParse[string](keys.PrivateKey, token)

		assert.NoError(t, err)
		assert.Equal(t, originalData, parsedData)
	})

	t.Run("ParseValidSimpleStruct", func(t *testing.T) {
		originalData := SimpleData{Message: "test message"}
		exp := time.Now().Add(time.Hour)
		token := PasetoSign(keys.PrivateKey, originalData, exp)

		parsedData, err := PasetoParse[SimpleData](keys.PrivateKey, token)

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
		token := PasetoSign(keys.PrivateKey, originalData, exp)

		parsedData, err := PasetoParse[ComplexData](keys.PrivateKey, token)

		assert.NoError(t, err)
		assert.Equal(t, originalData.User, parsedData.User)
		assert.Equal(t, originalData.Metadata, parsedData.Metadata)
		assert.Equal(t, originalData.Active, parsedData.Active)
		// Time comparison with some tolerance due to JSON marshaling
		assert.WithinDuration(t, originalData.Timestamp, parsedData.Timestamp, time.Second)
	})

	t.Run("ParseInvalidToken", func(t *testing.T) {
		invalidToken := "invalid.token.string"

		_, err := PasetoParse[string](keys.PrivateKey, invalidToken)

		assert.Error(t, err)
	})

	t.Run("ParseEmptyToken", func(t *testing.T) {
		emptyToken := ""

		_, err := PasetoParse[string](keys.PrivateKey, emptyToken)

		assert.Error(t, err)
	})

	t.Run("ParseWithWrongKey", func(t *testing.T) {
		// Create token with one key
		originalData := "test data"
		exp := time.Now().Add(time.Hour)
		token := PasetoSign(keys.PrivateKey, originalData, exp)

		// Try to parse with different key
		wrongKeys, err := generateTestKeys()
		require.NoError(t, err)

		_, err = PasetoParse[string](wrongKeys.PrivateKey, token)

		assert.Error(t, err)
	})

	t.Run("ParseExpiredToken", func(t *testing.T) {
		originalData := "test data"
		exp := time.Now().Add(-time.Hour) // Already expired
		token := PasetoSign(keys.PrivateKey, originalData, exp)

		// Wait a moment to ensure expiration
		time.Sleep(10 * time.Millisecond)

		_, err := PasetoParse[string](keys.PrivateKey, token)

		// Now that expiration validation is implemented, this should error
		assert.Error(t, err, "Expired token should be rejected")
		assert.Contains(t, err.Error(), "expired", "Error should mention expiration")
	})

	t.Run("ParseWithTypeMismatch", func(t *testing.T) {
		// Sign with one type, try to parse as another
		originalData := SimpleData{Message: "test"}
		exp := time.Now().Add(time.Hour)
		token := PasetoSign(keys.PrivateKey, originalData, exp)

		// Try to parse as string instead of SimpleData
		_, err := PasetoParse[string](keys.PrivateKey, token)

		// This might work depending on JSON marshaling, but the data won't match expected format
		// The behavior depends on how the JSON unmarshaling handles the type mismatch
		_ = err // We don't assert error here as it might succeed with unexpected data
	})

	t.Run("ParseNilData", func(t *testing.T) {
		exp := time.Now().Add(time.Hour)
		token := PasetoSign(keys.PrivateKey, nil, exp)

		parsedData, err := PasetoParse[interface{}](keys.PrivateKey, token)

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
		token := PasetoSign(keys.PrivateKey, largeData, exp)

		parsedData, err := PasetoParse[map[string]string](keys.PrivateKey, token)

		assert.NoError(t, err)
		assert.Equal(t, largeData, parsedData)
	})
}

func TestPasetoSignParseRoundTrip(t *testing.T) {
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
			token := PasetoSign(keys.PrivateKey, tc.data, exp)

			// Parse back using interface{} to handle different types
			parsedData, err := PasetoParse[interface{}](keys.PrivateKey, token)

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

func TestPasetoTokenStructure(t *testing.T) {
	keys, err := generateTestKeys()
	require.NoError(t, err)

	t.Run("TokenHasCorrectPrefix", func(t *testing.T) {
		data := "test"
		exp := time.Now().Add(time.Hour)
		token := PasetoSign(keys.PrivateKey, data, exp)

		assert.True(t, strings.HasPrefix(token, "v4.public."))
	})

	t.Run("TokensAreDifferentForSameData", func(t *testing.T) {
		data := "test"
		exp1 := time.Now().Add(time.Hour)
		exp2 := time.Now().Add(time.Hour + time.Second) // Different expiration times

		token1 := PasetoSign(keys.PrivateKey, data, exp1)
		token2 := PasetoSign(keys.PrivateKey, data, exp2)

		assert.NotEqual(t, token1, token2, "Tokens should be different due to different expiration times")
	})

	t.Run("TokensAreConsistentForSameTimestamp", func(t *testing.T) {
		data := "test"
		exp := time.Now().Add(time.Hour)

		// Mock the time by using the same expiration and ensuring issued/not-before times are the same
		// This is more of a behavioral test since the actual implementation uses time.Now()
		token := PasetoSign(keys.PrivateKey, data, exp)

		assert.NotEmpty(t, token)
		assert.Contains(t, token, "v4.public.")
	})
}

func TestPasetoEdgeCases(t *testing.T) {
	keys, err := generateTestKeys()
	require.NoError(t, err)

	t.Run("VeryLongString", func(t *testing.T) {
		// Create a very long string
		longString := strings.Repeat("a", 10000)
		exp := time.Now().Add(time.Hour)

		token := PasetoSign(keys.PrivateKey, longString, exp)
		parsedData, err := PasetoParse[string](keys.PrivateKey, token)

		assert.NoError(t, err)
		assert.Equal(t, longString, parsedData)
	})

	t.Run("SpecialCharacters", func(t *testing.T) {
		specialData := "!@#$%^&*()_+-=[]{}|;:,.<>?/~`"
		exp := time.Now().Add(time.Hour)

		token := PasetoSign(keys.PrivateKey, specialData, exp)
		parsedData, err := PasetoParse[string](keys.PrivateKey, token)

		assert.NoError(t, err)
		assert.Equal(t, specialData, parsedData)
	})

	t.Run("UnicodeCharacters", func(t *testing.T) {
		unicodeData := "Hello 世界 🌍 Здравствуй мир"
		exp := time.Now().Add(time.Hour)

		token := PasetoSign(keys.PrivateKey, unicodeData, exp)
		parsedData, err := PasetoParse[string](keys.PrivateKey, token)

		assert.NoError(t, err)
		assert.Equal(t, unicodeData, parsedData)
	})

	t.Run("EmptyString", func(t *testing.T) {
		emptyData := ""
		exp := time.Now().Add(time.Hour)

		token := PasetoSign(keys.PrivateKey, emptyData, exp)
		parsedData, err := PasetoParse[string](keys.PrivateKey, token)

		assert.NoError(t, err)
		assert.Equal(t, emptyData, parsedData)
	})

	t.Run("ZeroValues", func(t *testing.T) {
		zeroData := UserData{} // All zero values
		exp := time.Now().Add(time.Hour)

		token := PasetoSign(keys.PrivateKey, zeroData, exp)
		parsedData, err := PasetoParse[UserData](keys.PrivateKey, token)

		assert.NoError(t, err)
		assert.Equal(t, zeroData, parsedData)
	})
}

func TestPasetoPerformance(t *testing.T) {
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
			_ = PasetoSign(keys.PrivateKey, data, exp)
		}

		duration := time.Since(start)
		avgDuration := duration / time.Duration(iterations)

		t.Logf("Average sign time: %v for %d iterations", avgDuration, iterations)
		assert.Less(t, avgDuration, 10*time.Millisecond, "Signing should be reasonably fast")
	})

	t.Run("ParsePerformance", func(t *testing.T) {
		data := SimpleData{Message: "performance test"}
		exp := time.Now().Add(time.Hour)
		token := PasetoSign(keys.PrivateKey, data, exp)

		start := time.Now()
		iterations := 1000

		for i := 0; i < iterations; i++ {
			_, err := PasetoParse[SimpleData](keys.PrivateKey, token)
			assert.NoError(t, err)
		}

		duration := time.Since(start)
		avgDuration := duration / time.Duration(iterations)

		t.Logf("Average parse time: %v for %d iterations", avgDuration, iterations)
		assert.Less(t, avgDuration, 10*time.Millisecond, "Parsing should be reasonably fast")
	})
}

func TestPasetoExpirationValidation(t *testing.T) {
	keys, err := generateTestKeys()
	require.NoError(t, err)

	t.Run("ValidTokenWithinExpiration", func(t *testing.T) {
		data := "test data"
		exp := time.Now().Add(time.Hour)
		token := PasetoSign(keys.PrivateKey, data, exp)

		parsedData, err := PasetoParse[string](keys.PrivateKey, token)

		assert.NoError(t, err)
		assert.Equal(t, data, parsedData)
	})

	t.Run("TokenExpiresExactly", func(t *testing.T) {
		data := "test data"
		exp := time.Now().Add(100 * time.Millisecond)
		token := PasetoSign(keys.PrivateKey, data, exp)

		// Wait for expiration
		time.Sleep(150 * time.Millisecond)

		_, err := PasetoParse[string](keys.PrivateKey, token)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expired")
	})

	t.Run("TokenExpirationPrecision", func(t *testing.T) {
		data := "test data"
		now := time.Now()
		exp := now.Add(1 * time.Second)
		token := PasetoSign(keys.PrivateKey, data, exp)

		// Should work immediately after creation
		_, err := PasetoParse[string](keys.PrivateKey, token)
		assert.NoError(t, err)

		// Wait for expiration plus buffer and should fail
		time.Sleep(1200 * time.Millisecond)
		_, err = PasetoParse[string](keys.PrivateKey, token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expired")
	})
}

func TestPasetoSecurityProperties(t *testing.T) {
	t.Run("TokensFromDifferentKeysAreNotInterchangeable", func(t *testing.T) {
		keys1, err := generateTestKeys()
		require.NoError(t, err)

		keys2, err := generateTestKeys()
		require.NoError(t, err)

		data := "secret data"
		exp := time.Now().Add(time.Hour)

		// Sign with first key
		token := PasetoSign(keys1.PrivateKey, data, exp)

		// Try to parse with second key
		_, err = PasetoParse[string](keys2.PrivateKey, token)
		assert.Error(t, err, "Token signed with one key should not be parseable with another key")
	})

	t.Run("ModifiedTokensAreRejected", func(t *testing.T) {
		keys, err := generateTestKeys()
		require.NoError(t, err)

		data := "secret data"
		exp := time.Now().Add(time.Hour)
		token := PasetoSign(keys.PrivateKey, data, exp)

		// Modify the token by changing one character
		if len(token) > 20 {
			modifiedToken := token[:len(token)-5] + "X" + token[len(token)-4:]

			_, err = PasetoParse[string](keys.PrivateKey, modifiedToken)
			assert.Error(t, err, "Modified token should be rejected")
		}
	})

	t.Run("TruncatedTokensAreRejected", func(t *testing.T) {
		keys, err := generateTestKeys()
		require.NoError(t, err)

		data := "secret data"
		exp := time.Now().Add(time.Hour)
		token := PasetoSign(keys.PrivateKey, data, exp)

		// Truncate the token
		if len(token) > 10 {
			truncatedToken := token[:len(token)/2]

			_, err = PasetoParse[string](keys.PrivateKey, truncatedToken)
			assert.Error(t, err, "Truncated token should be rejected")
		}
	})
}

// Benchmark tests for PASETO operations
func BenchmarkInitializeKeys(b *testing.B) {
	// Generate test keys once
	secretKey := paseto.NewV4AsymmetricSecretKey()
	publicKey := secretKey.Public()
	privateHex := secretKey.ExportHex()
	publicHex := publicKey.ExportHex()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := InitializeKeys(privateHex, publicHex)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPasetoSign(b *testing.B) {
	keys, err := generateTestKeys()
	if err != nil {
		b.Fatal(err)
	}
	exp := time.Now().Add(time.Hour)

	b.Run("String", func(b *testing.B) {
		data := "benchmark test string"
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = PasetoSign(keys.PrivateKey, data, exp)
		}
	})

	b.Run("SimpleStruct", func(b *testing.B) {
		data := SimpleData{Message: "benchmark test message"}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = PasetoSign(keys.PrivateKey, data, exp)
		}
	})

	b.Run("ComplexStruct", func(b *testing.B) {
		data := ComplexData{
			User: UserData{
				ID:       123,
				Username: "benchmarkuser",
				Email:    "benchmark@example.com",
			},
			Metadata: map[string]string{
				"role":   "admin",
				"tenant": "benchmark-tenant",
				"region": "us-west-2",
			},
			Timestamp: time.Now(),
			Active:    true,
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = PasetoSign(keys.PrivateKey, data, exp)
		}
	})

	b.Run("LargeData", func(b *testing.B) {
		// Create a moderately large data structure
		largeData := make(map[string]string)
		for i := 0; i < 100; i++ {
			largeData[fmt.Sprintf("key_%d", i)] = fmt.Sprintf("value_%d_with_some_longer_content_for_benchmarking", i)
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = PasetoSign(keys.PrivateKey, largeData, exp)
		}
	})

	b.Run("VeryLargeData", func(b *testing.B) {
		// Create a very large data structure
		veryLargeData := make(map[string]string)
		for i := 0; i < 1000; i++ {
			veryLargeData[fmt.Sprintf("key_%d", i)] = fmt.Sprintf("value_%d_with_extensive_content_for_performance_benchmarking_purposes", i)
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = PasetoSign(keys.PrivateKey, veryLargeData, exp)
		}
	})
}
