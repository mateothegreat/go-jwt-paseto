// Package jwt provides a set of functions to handle the creation and
// verification of tokens using the JWT library.
package jwt

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"
)

// Benchmark tests for JWT operations
func BenchmarkGenerateKeys(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := GenerateKeys()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkInitializeKeys(b *testing.B) {
	// Generate test keys once
	keys, err := generateTestKeys()
	if err != nil {
		b.Fatal(err)
	}

	privateKeyDER, err := x509.MarshalECPrivateKey(keys.PrivateKey)
	if err != nil {
		b.Fatal(err)
	}
	privateKeyBase64 := base64.URLEncoding.EncodeToString(privateKeyDER)

	publicKeyDER, err := x509.MarshalPKIXPublicKey(keys.PublicKey)
	if err != nil {
		b.Fatal(err)
	}
	publicKeyBase64 := base64.URLEncoding.EncodeToString(publicKeyDER)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := InitializeKeys(privateKeyBase64, publicKeyBase64)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkJWTSign(b *testing.B) {
	keys, err := generateTestKeys()
	if err != nil {
		b.Fatal(err)
	}
	exp := time.Now().Add(time.Hour)

	b.Run("String", func(b *testing.B) {
		data := "benchmark test string"
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := JWTSign(keys.PrivateKey, data, exp)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("SimpleStruct", func(b *testing.B) {
		data := SimpleData{Message: "benchmark test message"}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := JWTSign(keys.PrivateKey, data, exp)
			if err != nil {
				b.Fatal(err)
			}
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
			_, err := JWTSign(keys.PrivateKey, data, exp)
			if err != nil {
				b.Fatal(err)
			}
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
			_, err := JWTSign(keys.PrivateKey, largeData, exp)
			if err != nil {
				b.Fatal(err)
			}
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
			_, err := JWTSign(keys.PrivateKey, veryLargeData, exp)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkJWTParse(b *testing.B) {
	keys, err := generateTestKeys()
	if err != nil {
		b.Fatal(err)
	}
	exp := time.Now().Add(time.Hour)

	b.Run("String", func(b *testing.B) {
		data := "benchmark test string"
		token, err := JWTSign(keys.PrivateKey, data, exp)
		if err != nil {
			b.Fatal(err)
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := JWTParse[string](keys.PublicKey, token)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("SimpleStruct", func(b *testing.B) {
		data := SimpleData{Message: "benchmark test message"}
		token, err := JWTSign(keys.PrivateKey, data, exp)
		if err != nil {
			b.Fatal(err)
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := JWTParse[SimpleData](keys.PublicKey, token)
			if err != nil {
				b.Fatal(err)
			}
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
		token, err := JWTSign(keys.PrivateKey, data, exp)
		if err != nil {
			b.Fatal(err)
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := JWTParse[ComplexData](keys.PublicKey, token)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("LargeData", func(b *testing.B) {
		largeData := make(map[string]string)
		for i := 0; i < 100; i++ {
			largeData[fmt.Sprintf("key_%d", i)] = fmt.Sprintf("value_%d_with_some_longer_content_for_benchmarking", i)
		}
		token, err := JWTSign(keys.PrivateKey, largeData, exp)
		if err != nil {
			b.Fatal(err)
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := JWTParse[map[string]string](keys.PublicKey, token)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("VeryLargeData", func(b *testing.B) {
		veryLargeData := make(map[string]string)
		for i := 0; i < 1000; i++ {
			veryLargeData[fmt.Sprintf("key_%d", i)] = fmt.Sprintf("value_%d_with_extensive_content_for_performance_benchmarking_purposes", i)
		}
		token, err := JWTSign(keys.PrivateKey, veryLargeData, exp)
		if err != nil {
			b.Fatal(err)
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := JWTParse[map[string]string](keys.PublicKey, token)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkJWTSignParseRoundTrip(b *testing.B) {
	keys, err := generateTestKeys()
	if err != nil {
		b.Fatal(err)
	}
	exp := time.Now().Add(time.Hour)

	b.Run("String", func(b *testing.B) {
		data := "benchmark test string"
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			token, err := JWTSign(keys.PrivateKey, data, exp)
			if err != nil {
				b.Fatal(err)
			}
			_, err = JWTParse[string](keys.PublicKey, token)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("SimpleStruct", func(b *testing.B) {
		data := SimpleData{Message: "benchmark test message"}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			token, err := JWTSign(keys.PrivateKey, data, exp)
			if err != nil {
				b.Fatal(err)
			}
			_, err = JWTParse[SimpleData](keys.PublicKey, token)
			if err != nil {
				b.Fatal(err)
			}
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
			},
			Timestamp: time.Now(),
			Active:    true,
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			token, err := JWTSign(keys.PrivateKey, data, exp)
			if err != nil {
				b.Fatal(err)
			}
			_, err = JWTParse[ComplexData](keys.PublicKey, token)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkJWTMemoryAllocation(b *testing.B) {
	keys, err := generateTestKeys()
	if err != nil {
		b.Fatal(err)
	}
	exp := time.Now().Add(time.Hour)

	b.Run("SignMemoryAllocation", func(b *testing.B) {
		data := SimpleData{Message: "memory allocation test"}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := JWTSign(keys.PrivateKey, data, exp)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("ParseMemoryAllocation", func(b *testing.B) {
		data := SimpleData{Message: "memory allocation test"}
		token, err := JWTSign(keys.PrivateKey, data, exp)
		if err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := JWTParse[SimpleData](keys.PublicKey, token)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("RoundTripMemoryAllocation", func(b *testing.B) {
		data := SimpleData{Message: "memory allocation test"}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			token, err := JWTSign(keys.PrivateKey, data, exp)
			if err != nil {
				b.Fatal(err)
			}
			_, err = JWTParse[SimpleData](keys.PublicKey, token)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkJWTTokenSizes(b *testing.B) {
	keys, err := generateTestKeys()
	if err != nil {
		b.Fatal(err)
	}
	exp := time.Now().Add(time.Hour)

	// Benchmark different payload sizes
	payloadSizes := []struct {
		name string
		data interface{}
	}{
		{"Tiny", "x"},
		{"Small", strings.Repeat("x", 100)},
		{"Medium", strings.Repeat("x", 1000)},
		{"Large", strings.Repeat("x", 10000)},
		{"VeryLarge", strings.Repeat("x", 100000)},
	}

	for _, ps := range payloadSizes {
		b.Run(fmt.Sprintf("Sign_%s", ps.name), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := JWTSign(keys.PrivateKey, ps.data, exp)
				if err != nil {
					b.Fatal(err)
				}
			}
		})

		b.Run(fmt.Sprintf("Parse_%s", ps.name), func(b *testing.B) {
			token, err := JWTSign(keys.PrivateKey, ps.data, exp)
			if err != nil {
				b.Fatal(err)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := JWTParse[string](keys.PublicKey, token)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkJWTConcurrency(b *testing.B) {
	keys, err := generateTestKeys()
	if err != nil {
		b.Fatal(err)
	}
	exp := time.Now().Add(time.Hour)
	data := SimpleData{Message: "concurrency test"}

	b.Run("ConcurrentSign", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				_, err := JWTSign(keys.PrivateKey, data, exp)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	})

	b.Run("ConcurrentParse", func(b *testing.B) {
		token, err := JWTSign(keys.PrivateKey, data, exp)
		if err != nil {
			b.Fatal(err)
		}
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				_, err := JWTParse[SimpleData](keys.PublicKey, token)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	})

	b.Run("ConcurrentRoundTrip", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				token, err := JWTSign(keys.PrivateKey, data, exp)
				if err != nil {
					b.Fatal(err)
				}
				_, err = JWTParse[SimpleData](keys.PublicKey, token)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	})
}
