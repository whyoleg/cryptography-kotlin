# Contributing to cryptography-kotlin

This guide covers project overview, architecture, development setup, building, testing, and contribution workflow.

## Prerequisites

- JDK 17+ (for building)
- Gradle 9.x (wrapper included)
- [`just`](https://github.com/casey/just) command runner (`brew install just` on macOS)

## Project Structure

```
cryptography-kotlin/
├── cryptography-core/           # Public API (algorithms, materials, operations)
├── cryptography-random/         # Secure random number generation
├── cryptography-bigint/         # Big integer support
├── cryptography-serialization/
│   ├── pem/                     # PEM encoding/decoding
│   └── asn1/                    # ASN.1/DER encoding/decoding
│       └── modules/             # Standard ASN.1 structures (PKCS#8, X.509, etc.)
├── cryptography-providers/
│   ├── base/                    # Shared provider utilities
│   ├── tests/                   # Shared test infrastructure
│   ├── jdk/                     # JVM provider (JCA)
│   ├── webcrypto/               # JS/WasmJS provider
│   ├── apple/                   # Apple CommonCrypto/Security provider
│   ├── cryptokit/               # Apple CryptoKit provider
│   ├── openssl3/
│   │   ├── api/                 # OpenSSL provider API
│   │   ├── shared/              # Shared OpenSSL (link at runtime)
│   │   ├── prebuilt/            # Prebuilt OpenSSL (bundled)
│   │   └── test/                # OpenSSL-specific tests
│   └── optimal/                 # Auto-selecting composite provider
├── cryptography-bom/            # Bill of Materials
├── cryptography-version-catalog/# Gradle version catalog
├── build-logic/                 # Custom Gradle plugins
└── docs/                        # MkDocs documentation
```

## Code Architecture

### Algorithm & Provider Patterns

**Algorithm APIs** are defined in `cryptography-core/src/commonMain/kotlin/algorithms/`. Look at existing algorithms (e.g., `HMAC.kt`,
`AES.kt`) as reference when adding new ones.

**Provider implementations** go in the provider's `algorithms/` directory and are registered in the provider's `getOrNull()` method.

### API Annotations

| Annotation                                               | Usage                                      |
|----------------------------------------------------------|--------------------------------------------|
| `@CryptographyProviderApi`                               | Provider implementation internals          |
| `@DelicateCryptographyApi`                               | Dangerous APIs (ECB, MD5, SHA1, RIPEMD160) |
| `@SubclassOptInRequired(CryptographyProviderApi::class)` | Interfaces for provider implementation     |

### Naming Conventions

| Element                  | Pattern                                                    | Example                      |
|--------------------------|------------------------------------------------------------|------------------------------|
| Provider algorithm class | `<Provider><Algorithm>`                                    | `JdkAesGcm`, `Openssl3Ecdsa` |
| Provider key class       | `<Provider><Algorithm>Key`                                 | `JdkAesGcmKey`               |
| Package                  | `dev.whyoleg.cryptography.providers.<provider>.algorithms` |                              |
| Test class (generated)   | `<Provider>_<TestType>_<Algorithm>Test`                    | `JDK_Default_AesGcmTest`     |

### Deprecation Handling

When deprecating APIs:

- Use `@Deprecated` with `DeprecationLevel.ERROR`
- Throw exception if implementation is not feasible
- Never silently ignore deprecated behavior

## Building

### Build Specific Modules (Recommended)

Building specific modules is faster than building everything:

```bash
# Build a provider module (short form, auto-prefixed with :cryptography-)
just build provider-jdk

# Build core API
just build core

# Or use the full Gradle module path
just build :cryptography-provider-openssl3-api
```

### Build All Modules

```bash
# Skip tests and native linking for faster builds
just build

# Link all native binaries
just link
```

## Running Tests

### Provider Tests (Recommended)

Run tests for a specific provider rather than all providers:

```bash
# JVM tests
just test-provider-jdk

# WebCrypto tests (WasmJS on Node.js)
just test-provider-webcrypto

# Native tests (macOS ARM)
just test-provider-openssl3
just test-provider-cryptokit
just test-provider-apple

# Filter by test class (wildcard supported)
just test-provider-jdk "*AesGcmTest*"
```

### Compatibility Tests

Cross-provider compatibility tests use a two-phase pipeline via a local testtool server:

1. **Generate** – each provider creates test vectors (keys, ciphertexts, signatures, etc.) and stores them via the testtool server
2. **Validate** – each provider reads *all* generated test vectors and verifies them, ensuring cross-provider compatibility

The testtool server starts automatically when running compat steps – no manual server management needed. Server data persists in
`build/testtool/server-storage/` between invocations within the same generate/validate cycle.

#### Workflow

```bash
# 1. Clean previous server storage (start fresh)
just compat-clean

# 2. Generate test vectors for each provider you want to test
just test-provider-jdk --step generate
just test-provider-cryptokit --step generate

# 3. Validate test vectors for each provider
just test-provider-jdk --step validate
just test-provider-cryptokit --step validate
```

Skip `compat-clean` only when intentionally adding more providers on top of an existing generate run.

To filter by a specific algorithm, pass its test class as the first argument:

```bash
just test-provider-jdk "*AesGcmCompatibilityTest*" --step generate
just test-provider-cryptokit "*AesGcmCompatibilityTest*" --step generate
just test-provider-jdk "*AesGcmCompatibilityTest*" --step validate
just test-provider-cryptokit "*AesGcmCompatibilityTest*" --step validate
```

#### Provider Reference

| Provider           | `just` recipe             | Notes          |
|--------------------|---------------------------|----------------|
| JDK                | `test-provider-jdk`       |                |
| Apple CommonCrypto | `test-provider-apple`     | Requires macOS |
| CryptoKit          | `test-provider-cryptokit` | Requires macOS |
| OpenSSL3 Prebuilt  | `test-provider-openssl3`  |                |
| WebCrypto (WasmJS) | `test-provider-webcrypto` |                |

### Test Types

Tests are organized in `cryptography-provider-tests`:

| Type          | Directory        | Purpose                                                         |
|---------------|------------------|-----------------------------------------------------------------|
| Default       | `default/`       | Basic functionality tests (encryption roundtrips, key encoding) |
| Compatibility | `compatibility/` | Cross-provider/cross-platform validation                        |
| Test Vectors  | `testvectors/`   | RFC/specification compliance tests                              |

### Platform Limitations

- On macOS ARM machines, only `macosArm64` tests can be run locally
- `linuxX64`, `mingwX64`, etc. require their respective platforms
- Use CI for full cross-platform testing

| Issue                   | Platforms Affected                             |
|-------------------------|------------------------------------------------|
| Native linking          | All native targets need explicit linking       |
| WebCrypto limitations   | Many algorithms unsupported (SHA3, CMAC, etc.) |
| CryptoKit limitations   | No AES-CBC, AES-CTR, RSA encryption            |
| JDK version differences | Algorithms vary by Java version                |

## Adding a New Algorithm

### 1. Define the Interface

Create the algorithm interface in `cryptography-core/src/commonMain/kotlin/algorithms/`:

```kotlin
@SubclassOptInRequired(CryptographyProviderApi::class)
interface MyAlgorithm : CryptographyAlgorithm {
    override val id: CryptographyAlgorithmId<MyAlgorithm> get() = Companion

    companion object : CryptographyAlgorithmId<MyAlgorithm>("MY-ALGORITHM")

    fun keyDecoder(): KeyDecoder<Key.Format, Key>
    fun keyGenerator(): KeyGenerator<Key>

    @SubclassOptInRequired(CryptographyProviderApi::class)
    interface Key : EncodableKey<Key.Format> {
        sealed class Format : KeyFormat { /* RAW, DER, PEM, JWK */ }
        // operations: cipher(), signatureGenerator(), etc.
    }
}
```

### 2. Implement in Providers

Add implementation in each provider's `algorithms/` directory.

### 3. Register the Algorithm

Register in provider's `getOrNull()` method.

### 4. Add Tests

1. Register in `build-logic/src/main/kotlin/ckbuild/tests/GenerateProviderTestsTask.kt`
2. Create test classes in `cryptography-providers/tests/src/commonMain/kotlin/`:
    - Default test in `default/`
    - Compatibility test in `compatibility/`
    - Test vectors in `testvectors/` (if available)

### 5. Update Public API

```bash
just update-abi
```

## CI/CD

GitHub Actions runs on PRs and pushes:

- Build validation across all platforms
- Tests on Linux, macOS, Windows
- Android emulator tests

Check workflow results in the Actions tab before merging.

## Documentation

- Update `docs/` when adding user-facing features
- API documentation is auto-generated via Dokka

```bash
just docs
```
