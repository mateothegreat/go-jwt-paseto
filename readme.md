# JWT vs PASETO Performance & Security Comparison

This repository provides a comprehensive comparison between JWT and PASETO implementations with Go, covering both performance benchmarks and security properties.

> [!NOTE]
> Feeeling froggy?
> `/ship-it` with a `go install github.com/mateothegreat/go-jwt-paseto@latest` and you'll be able to use the `jwt` and `paseto` packages in your own project for POC'ing and then you can decide which one is right for _you_.

### What's wrong with JWT?

Nothing. It has a place in the ecosystem and is a great tool for many use cases.

JWT's popularity stems from its ubiquity and tooling, but that ease can mask complexity—especially around algorithm selection, claim validation, and expiration enforcement.

### What's wrong with PASETO?

Nothing. It has a place in the ecosystem and is a great tool for many use cases.

PASETO's popularity stems from its security properties, performance, and clarity of design. It enforces safer defaults and avoids common pitfalls like algorithm confusion.

## Overview

What this demonstration provides:

- 🤩 Comprehensive test coverage with handcrafted edge-case scenarios.
- 📈 Extensive benchmark coverage—because performance matters.
- 🔄 Consistent implementations.
- 📚 Healthy documentation to help you reason about what the code is _doing_.
- 🔒 Security-oriented development™ practice to ensure robustness.

## CLI Key Generation

Generate a fresh PASETO v4 asymmetric key pair and print both values as hex:

```sh
go run ./cmd/paseto-keygen
```

Example output:

```text
private_hex=<hex-encoded-private-key>
public_hex=<hex-encoded-public-key>
```

## Performance Comparison

### Key Generation & Initialization

| Operation          | JWT           | PASETO        | Winner |
| ------------------ | ------------- | ------------- | ------ |
| Key Generation     | ~13,324 ns/op | N/A*          | JWT    |
| Key Initialization | ~14,339 ns/op | ~27,460 ns/op | JWT    |

> **Note**: PASETO uses generated keys directly for symmetric encryption; asymmetric key generation (Ed25519) is measurable but not benchmarked here.

### Token Signing Performance

| Data Type       | JWT (ns/op) | JWT (B/op) | JWT (allocs/op) | PASETO (ns/op) | PASETO (B/op) | PASETO (allocs/op) | Winner          |
| --------------- | ----------- | ---------- | --------------- | -------------- | ------------- | ------------------ | --------------- |
| String          | ~28,528     | 8,824      | 106             | ~28,108        | 3,205         | 44                 | PASETO (memory) |
| Simple Struct   | ~28,561     | 8,904      | 106             | ~28,475        | 3,357         | 44                 | PASETO (memory) |
| Complex Struct  | ~36,454     | 10,685     | 114             | ~30,875        | 5,025         | 51                 | PASETO          |
| Large Data      | ~64,841     | 69,399     | 307             | ~96,630        | 56,859        | 242                | JWT (speed)     |
| Very Large Data | ~517,259    | 763,500    | 2,110           | ~1,089,027     | 712,679       | 2,047              | JWT (speed)     |

### Token Parsing Performance

| Data Type       | JWT (ns/op) | JWT (B/op) | JWT (allocs/op) | PASETO (ns/op) | PASETO (B/op) | PASETO (allocs/op) | Winner      |
| --------------- | ----------- | ---------- | --------------- | -------------- | ------------- | ------------------ | ----------- |
| String          | ~65,315     | 4,552      | 76              | ~59,347        | 3,713         | 72                 | PASETO      |
| Simple Struct   | ~67,460     | 4,616      | 78              | ~59,419        | 3,905         | 76                 | PASETO      |
| Complex Struct  | ~68,542     | 5,952      | 94              | ~63,793        | 4,890         | 91                 | PASETO      |
| Large Data      | ~144,105    | 61,617     | 392             | ~150,619       | 47,110        | 384                | JWT (speed) |
| Very Large Data | ~858,143    | 847,571    | 3,107           | ~1,287,302     | 627,891       | 3,096              | JWT (speed) |

### Round-Trip Performance (Sign + Parse)

| Data Type      | JWT (ns/op) | JWT (B/op) | JWT (allocs/op) | PASETO (ns/op) | PASETO (B/op) | PASETO (allocs/op) | Winner |
| -------------- | ----------- | ---------- | --------------- | -------------- | ------------- | ------------------ | ------ |
| String         | ~104,558    | 13,372     | 182             | ~89,117        | 6,914         | 116                | PASETO |
| Simple Struct  | ~107,710    | 13,517     | 184             | ~100,560       | 7,266         | 120                | PASETO |
| Complex Struct | ~101,715    | 16,241     | 203             | ~97,172        | 10,826        | 139                | PASETO |

### Memory Allocation Comparison

- **PASETO uses ~40–60% fewer allocations** across all payload sizes.
- **For small/medium payloads**, PASETO is significantly more memory-efficient.
- **For very large payloads**, JWT is slightly more efficient due to its simpler structure.

## Security Properties

### ✅ Security Features Validated

1. **Key Isolation**: Tokens signed with different keys are not interchangeable.
2. **Tamper Detection**: Modified tokens are properly rejected.
3. **Truncation Protection**: Truncated tokens are properly rejected.
4. **Expiration Validation**: Expired tokens are rejected (JWT via config; PASETO requires explicit validation).
5. **Type Safety**: Generic type system prevents type confusion attacks.

### Key Differences

| Security Aspect          | JWT                        | PASETO                        | Verdict                                |
| ------------------------ | -------------------------- | ----------------------------- | -------------------------------------- |
| Algorithm Agility        | ✅ Multiple algorithms      | ✅ Fixed per version           | PASETO (safer)                         |
| Expiration Enforcement   | ⚠️ Optional via config      | ⚠️ Manual validation required  | Tie (both require developer diligence) |
| Token Structure          | ✅ Header.Payload.Signature | ✅ Version.Purpose.Payload     | PASETO (clearer)                       |
| Cryptographic Primitives | ✅ HMAC, RSA, ECDSA         | ✅ Ed25519, XChaCha20-Poly1305 | PASETO (modern)                        |

> PASETO’s design forces developers to be explicit, which can be safer in high-assurance systems. JWT libraries often auto-check expiration, but only if configured correctly.

## Concurrency Performance

| Operation        | JWT (ns/op) | PASETO (ns/op) | Winner            |
| ---------------- | ----------- | -------------- | ----------------- |
| Concurrent Sign  | ~7,723      | ~5,501         | PASETO            |
| Concurrent Parse | ~11,478     | ~11,143        | PASETO (marginal) |
| Round-Trip       | ~19,852     | ~16,094        | PASETO            |

✅ PASETO handles concurrent operations more efficiently, making it ideal for high-throughput systems.

## Recommendations

### Choose JWT When:
- You need automatic expiration validation
- Working with very large payloads (>100KB)
- Integration with existing JWT-based systems is required
- Algorithm flexibility is needed

### Choose PASETO When:
- Memory efficiency is critical
- High concurrency is expected
- Security is the top priority
- Working with small to medium payloads (<100KB)
- You want modern cryptographic primitives

## Payload Size Recommendations

| Payload Size | Recommended | Reason                                |
| ------------ | ----------- | ------------------------------------- |
| < 1KB        | PASETO      | Better memory efficiency and speed    |
| 1KB – 10KB   | PASETO      | Balanced performance and security     |
| 10KB – 100KB | JWT         | Better performance for large payloads |
| > 100KB      | JWT         | Significantly better performance      |

## Conclusion

**Winner by Category:**

- **Overall Performance**: Tie (depends on use case)
- **Memory Efficiency**: PASETO
- **Security**: PASETO
- **Large Payload Performance**: JWT
- **Concurrency**: PASETO
- **Ease of Use**: JWT

**Recommendation**: Use **PASETO** for new projects requiring high security and memory efficiency with small to medium payloads. Use **JWT** for large payloads or when integrating with existing JWT infrastructure.

## Benchmark Results

```sh
../go-jwt-paseto 🌱 main [?] ✗ make bench                      
go test -bench=. -benchmem . ./jwt
goos: darwin
goarch: arm64
pkg: github.com/mateothegreat/go-jwt-paseto
cpu: Apple M1 Max
BenchmarkPasetoParse/String-10                     19654             61264 ns/op            3921 B/op         76 allocs/op
BenchmarkPasetoParse/SimpleStruct-10               19526             59469 ns/op            4113 B/op         80 allocs/op
BenchmarkPasetoParse/ComplexStruct-10              19048             62453 ns/op            5098 B/op         95 allocs/op
BenchmarkPasetoParse/LargeData-10                   8241            147518 ns/op           47317 B/op        388 allocs/op
BenchmarkPasetoParse/VeryLargeData-10               1008           1190245 ns/op          628119 B/op       3100 allocs/op
BenchmarkPasetoSignParseRoundTrip/String-10                13854             86489 ns/op            7122 B/op        120 allocs/op
BenchmarkPasetoSignParseRoundTrip/SimpleStruct-10          13023            101668 ns/op            7475 B/op        124 allocs/op
BenchmarkPasetoSignParseRoundTrip/ComplexStruct-10         12721            103823 ns/op           11034 B/op        143 allocs/op
BenchmarkPasetoMemoryAllocation/SignMemoryAllocation-10                    43807             28540 ns/op            3357 B/op         44 allocs/op
BenchmarkPasetoMemoryAllocation/ParseMemoryAllocation-10                   20155             62646 ns/op            4114 B/op         80 allocs/op
BenchmarkPasetoMemoryAllocation/RoundTripMemoryAllocation-10               12944             87192 ns/op            7475 B/op        124 allocs/op
BenchmarkPasetoTokenSizes/Sign_Tiny-10                                     41811             29864 ns/op            2948 B/op         43 allocs/op
BenchmarkPasetoTokenSizes/Parse_Tiny-10                                    20356             65514 ns/op            3793 B/op         75 allocs/op
BenchmarkPasetoTokenSizes/Sign_Small-10                                    42700             28938 ns/op            4046 B/op         43 allocs/op
BenchmarkPasetoTokenSizes/Parse_Small-10                                   18825             60344 ns/op            4498 B/op         76 allocs/op
BenchmarkPasetoTokenSizes/Sign_Medium-10                                   32300             35504 ns/op           14173 B/op         43 allocs/op
BenchmarkPasetoTokenSizes/Parse_Medium-10                                  17362             72123 ns/op           10933 B/op         76 allocs/op
BenchmarkPasetoTokenSizes/Sign_Large-10                                    10000            110636 ns/op           75420 B/op         41 allocs/op
BenchmarkPasetoTokenSizes/Parse_Large-10                                    7866            155395 ns/op           54217 B/op         75 allocs/op
BenchmarkPasetoTokenSizes/Sign_VeryLarge-10                                 1557            756676 ns/op          758392 B/op         43 allocs/op
BenchmarkPasetoTokenSizes/Parse_VeryLarge-10                                1210            986434 ns/op          535735 B/op         75 allocs/op
BenchmarkPasetoConcurrency/ConcurrentSign-10                              216289              5078 ns/op            3217 B/op         44 allocs/op
BenchmarkPasetoConcurrency/ConcurrentParse-10                             116119              9950 ns/op            4011 B/op         80 allocs/op
BenchmarkPasetoConcurrency/ConcurrentRoundTrip-10                          77720             15559 ns/op            7236 B/op        124 allocs/op
BenchmarkInitializeKeys-10                                                 64270             18695 ns/op             192 B/op          5 allocs/op
BenchmarkPasetoSign/String-10                                              43429             28336 ns/op            3205 B/op         44 allocs/op
BenchmarkPasetoSign/SimpleStruct-10                                        37423             27538 ns/op            3357 B/op         44 allocs/op
BenchmarkPasetoSign/ComplexStruct-10                                       40060             29699 ns/op            5025 B/op         51 allocs/op
BenchmarkPasetoSign/LargeData-10                                           13218             91074 ns/op           56860 B/op        242 allocs/op
BenchmarkPasetoSign/VeryLargeData-10                                        1370            889633 ns/op          709442 B/op       2046 allocs/op
PASS
ok      github.com/mateothegreat/go-jwt-paseto  49.866s
goos: darwin
goarch: arm64
pkg: github.com/mateothegreat/go-jwt-paseto/jwt
cpu: Apple M1 Max
BenchmarkGenerateKeys-10                   94039             13247 ns/op            1000 B/op         17 allocs/op
BenchmarkInitializeKeys-10                 84576             13979 ns/op            1696 B/op         31 allocs/op
BenchmarkJWTSign/String-10                 36080             28008 ns/op            8824 B/op        106 allocs/op
BenchmarkJWTSign/SimpleStruct-10           43452             28153 ns/op            8904 B/op        106 allocs/op
BenchmarkJWTSign/ComplexStruct-10          39272             29119 ns/op           10684 B/op        114 allocs/op
BenchmarkJWTSign/LargeData-10              18891             61890 ns/op           69429 B/op        307 allocs/op
BenchmarkJWTSign/VeryLargeData-10           2523            479498 ns/op          762431 B/op       2110 allocs/op
BenchmarkJWTParse/String-10                18606             63336 ns/op            4552 B/op         76 allocs/op
BenchmarkJWTParse/SimpleStruct-10          18824             64622 ns/op            4616 B/op         78 allocs/op
BenchmarkJWTParse/ComplexStruct-10         18139             66315 ns/op            5952 B/op         94 allocs/op
BenchmarkJWTParse/LargeData-10              9765            128674 ns/op           61617 B/op        392 allocs/op
BenchmarkJWTParse/VeryLargeData-10          1586            797797 ns/op          847571 B/op       3107 allocs/op
BenchmarkJWTSignParseRoundTrip/String-10                   12958             92585 ns/op           13372 B/op        182 allocs/op
BenchmarkJWTSignParseRoundTrip/SimpleStruct-10             12912             93132 ns/op           13516 B/op        184 allocs/op
BenchmarkJWTSignParseRoundTrip/ComplexStruct-10            12196             95512 ns/op           16239 B/op        203 allocs/op
BenchmarkJWTMemoryAllocation/SignMemoryAllocation-10               43232             27736 ns/op            8904 B/op        106 allocs/op
BenchmarkJWTMemoryAllocation/ParseMemoryAllocation-10              18842             67113 ns/op            4616 B/op         78 allocs/op
BenchmarkJWTMemoryAllocation/RoundTripMemoryAllocation-10          12638             94745 ns/op           13517 B/op        184 allocs/op
BenchmarkJWTTokenSizes/Sign_Tiny-10                                42672             28185 ns/op            8664 B/op        106 allocs/op
BenchmarkJWTTokenSizes/Parse_Tiny-10                               17263             64686 ns/op            4432 B/op         75 allocs/op
BenchmarkJWTTokenSizes/Sign_Small-10                               41091             32895 ns/op            9434 B/op        106 allocs/op
BenchmarkJWTTokenSizes/Parse_Small-10                              17872             65683 ns/op            4912 B/op         76 allocs/op
BenchmarkJWTTokenSizes/Sign_Medium-10                              38210             31442 ns/op           17065 B/op        106 allocs/op
BenchmarkJWTTokenSizes/Parse_Medium-10                             17226             70197 ns/op           10896 B/op         77 allocs/op
BenchmarkJWTTokenSizes/Sign_Large-10                               19928             57905 ns/op           86643 B/op        106 allocs/op
BenchmarkJWTTokenSizes/Parse_Large-10                               9555            134839 ns/op           81937 B/op         80 allocs/op
BenchmarkJWTTokenSizes/Sign_VeryLarge-10                            3853            317032 ns/op          831852 B/op        108 allocs/op
BenchmarkJWTTokenSizes/Parse_VeryLarge-10                           1800            659602 ns/op          755235 B/op         83 allocs/op
BenchmarkJWTConcurrency/ConcurrentSign-10                         162852              7681 ns/op            8881 B/op        106 allocs/op
BenchmarkJWTConcurrency/ConcurrentParse-10                        109900             11122 ns/op            4576 B/op         78 allocs/op
BenchmarkJWTConcurrency/ConcurrentRoundTrip-10                     60620             21717 ns/op           13458 B/op        184 allocs/op
PASS
ok      github.com/mateothegreat/go-jwt-paseto/jwt      51.534s
```