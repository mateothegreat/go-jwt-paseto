// Package paseto provides a set of functions to handle the creation and
// verification of tokens using the PASETO library.
package paseto

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func BenchmarkPasetoParse(b *testing.B) {
	keys, err := generateTestKeys()
	if err != nil {
		b.Fatal(err)
	}
	exp := time.Now().Add(time.Hour)

	b.Run("String", func(b *testing.B) {
		data := "benchmark test string"
		token := PasetoSign(keys.PrivateKey, data, exp)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := PasetoParse[string](keys.PrivateKey, token)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("SimpleStruct", func(b *testing.B) {
		data := SimpleData{Message: "benchmark test message"}
		token := PasetoSign(keys.PrivateKey, data, exp)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := PasetoParse[SimpleData](keys.PrivateKey, token)
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
		token := PasetoSign(keys.PrivateKey, data, exp)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := PasetoParse[ComplexData](keys.PrivateKey, token)
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
		token := PasetoSign(keys.PrivateKey, largeData, exp)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := PasetoParse[map[string]string](keys.PrivateKey, token)
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
		token := PasetoSign(keys.PrivateKey, veryLargeData, exp)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := PasetoParse[map[string]string](keys.PrivateKey, token)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkPasetoSignParseRoundTrip(b *testing.B) {
	keys, err := generateTestKeys()
	if err != nil {
		b.Fatal(err)
	}
	exp := time.Now().Add(time.Hour)

	b.Run("String", func(b *testing.B) {
		data := "benchmark test string"
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			token := PasetoSign(keys.PrivateKey, data, exp)
			_, err := PasetoParse[string](keys.PrivateKey, token)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("SimpleStruct", func(b *testing.B) {
		data := SimpleData{Message: "benchmark test message"}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			token := PasetoSign(keys.PrivateKey, data, exp)
			_, err := PasetoParse[SimpleData](keys.PrivateKey, token)
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
			token := PasetoSign(keys.PrivateKey, data, exp)
			_, err := PasetoParse[ComplexData](keys.PrivateKey, token)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkPasetoMemoryAllocation(b *testing.B) {
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
			_ = PasetoSign(keys.PrivateKey, data, exp)
		}
	})

	b.Run("ParseMemoryAllocation", func(b *testing.B) {
		data := SimpleData{Message: "memory allocation test"}
		token := PasetoSign(keys.PrivateKey, data, exp)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := PasetoParse[SimpleData](keys.PrivateKey, token)
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
			token := PasetoSign(keys.PrivateKey, data, exp)
			_, err := PasetoParse[SimpleData](keys.PrivateKey, token)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkPasetoTokenSizes(b *testing.B) {
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
				_ = PasetoSign(keys.PrivateKey, ps.data, exp)
			}
		})

		b.Run(fmt.Sprintf("Parse_%s", ps.name), func(b *testing.B) {
			token := PasetoSign(keys.PrivateKey, ps.data, exp)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := PasetoParse[string](keys.PrivateKey, token)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkPasetoConcurrency(b *testing.B) {
	keys, err := generateTestKeys()
	if err != nil {
		b.Fatal(err)
	}
	exp := time.Now().Add(time.Hour)
	data := SimpleData{Message: "concurrency test"}

	b.Run("ConcurrentSign", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				_ = PasetoSign(keys.PrivateKey, data, exp)
			}
		})
	})

	b.Run("ConcurrentParse", func(b *testing.B) {
		token := PasetoSign(keys.PrivateKey, data, exp)
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				_, err := PasetoParse[SimpleData](keys.PrivateKey, token)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	})

	b.Run("ConcurrentRoundTrip", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				token := PasetoSign(keys.PrivateKey, data, exp)
				_, err := PasetoParse[SimpleData](keys.PrivateKey, token)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	})
}
