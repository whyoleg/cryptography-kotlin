# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

cryptography-kotlin is a type-safe Multiplatform cryptography library for Kotlin. It does NOT implement cryptographic algorithms itself but
wraps well-known platform-specific implementations with a unified Kotlin API:

- **OpenSSL 3.x** - for Linux, MinGW, Android Native
- **WebCrypto API** - for JS and WasmJS (browser and Node.js)
- **CryptoKit** - for Apple platforms (macOS, iOS, watchOS, tvOS)
- **CommonCrypto/Security frameworks** - for Apple platforms (legacy algorithms)
- **JCA (Java Cryptography Architecture)** - for JVM and Android

The library provides uniform behavior across platforms with aligned defaults, so the same code produces the same results regardless of the
underlying provider.

## Supported Algorithms

| Category          | Algorithms                                                                        |
|-------------------|-----------------------------------------------------------------------------------|
| Digests           | MD5, SHA1, SHA224, SHA256, SHA384, SHA512, SHA3-224/256/384/512, RIPEMD160        |
| MACs              | HMAC, AES-CMAC                                                                    |
| Symmetric Ciphers | AES-GCM, AES-CBC, AES-CTR, AES-CFB, AES-CFB8, AES-OFB, AES-ECB, ChaCha20-Poly1305 |
| Asymmetric        | RSA-OAEP, RSA-PKCS1 (sign/encrypt), RSA-PSS, RSA-RAW, ECDSA, ECDH, DH             |
| Key Derivation    | PBKDF2, HKDF                                                                      |

Not all algorithms are supported by all providers. Use `provider.getOrNull(algorithmId)` to check availability.

## Build Commands

```bash
# Build specific modules (recommended - faster than building everything)
./gradlew :cryptography-provider-jdk:build -Pckbuild.skipTestTasks=true -Pckbuild.skipLinkTasks=true
./gradlew :cryptography-provider-openssl3-api:build -Pckbuild.skipTestTasks=true -Pckbuild.skipLinkTasks=true

# Build all modules (skip tests and native linking for faster builds)
./gradlew build -Pckbuild.skipTestTasks=true -Pckbuild.skipLinkTasks=true

# Link all native binaries
./gradlew linkAll
```

**Note:** For native targets on macOS ARM machines, only `macosArm64` tests can be run locally. Other native targets (linuxX64, mingwX64,
etc.) require their respective platforms.

## Running Tests

**In most cases, run tests for a specific provider module rather than all providers.**

```bash
# Run tests for a specific provider (recommended)
./gradlew :cryptography-provider-jdk:jvmTest
./gradlew :cryptography-provider-webcrypto:jsTest
./gradlew :cryptography-provider-openssl3-prebuilt:macosArm64Test
./gradlew :cryptography-provider-cryptokit:macosArm64Test

# Run specific test class
./gradlew :cryptography-provider-jdk:jvmTest --tests "dev.whyoleg.cryptography.providers.jdk.JDK_Default_AesGcmTest"
```

### Test Types

Tests are in `cryptography-provider-tests`:

1. **Default Tests** (`default/`): Basic functionality tests (encryption roundtrips, key encoding)
2. **Compatibility Tests** (`compatibility/`): Cross-provider/cross-platform validation
3. **Test Vectors** (`testvectors/`): RFC/specification compliance tests

## Module Structure

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
│   ├── jdk/                     # JVM provider
│   ├── webcrypto/               # JS/WasmJS provider
│   ├── apple/                   # Apple CommonCrypto/Security provider
│   ├── cryptokit/               # Apple CryptoKit provider
│   ├── openssl3/
│   │   ├── api/                 # OpenSSL provider API
│   │   ├── shared/              # Shared OpenSSL (link at runtime)
│   │   ├── prebuilt/            # Prebuilt OpenSSL (bundled)
│   │   └── test/                # OpenSSL-specific tests
│   └── optimal/                 # Auto-selecting composite provider
└── build-logic/                 # Custom Gradle plugins
```

## Core API Architecture

### Materials API

The library uses a unified **Materials API** for both keys and algorithm parameters. This reduces code duplication and provides consistent
patterns.

**Base interfaces** in `cryptography-core/materials/`:

```kotlin
// Format marker
interface MaterialFormat { val name: String }

// Decode from bytes
interface MaterialDecoder<F : MaterialFormat, M> {
    fun decodeFromByteArrayBlocking(format: F, bytes: ByteArray): M
    suspend fun decodeFromByteArray(format: F, bytes: ByteArray): M
}

// Generate new material
interface MaterialGenerator<M> {
    fun generateBlocking(): M
    suspend fun generate(): M
}

// Encode to bytes
interface EncodableMaterial<F : MaterialFormat> {
    fun encodeToByteArrayBlocking(format: F): ByteArray
    suspend fun encodeToByteArray(format: F): ByteArray
}
```

**Key interfaces** extend the base Material interfaces for backwards compatibility:

```kotlin
interface KeyFormat : MaterialFormat
interface KeyDecoder<KF, K> : MaterialDecoder<KF, K>
interface KeyGenerator<K> : MaterialGenerator<K> {
    fun generateKeyBlocking(): K  // kept for compatibility
    suspend fun generateKey(): K
    // Delegates to generate()/generateBlocking()
}
interface EncodableKey<KF> : Key, EncodableMaterial<KF>
```

**Algorithm parameters** use Material* interfaces directly (no separate Parameter* hierarchy):

```kotlin
interface SomeAlgorithm {
    fun parametersDecoder(): MaterialDecoder<Parameters.Format, Parameters>
    fun parametersGenerator(size: BinarySize): MaterialGenerator<Parameters>

    interface Parameters : EncodableMaterial<Parameters.Format> {
        sealed class Format : MaterialFormat { ... }
    }
}
```

### Algorithm Pattern

All algorithms follow this structure:

```kotlin
@SubclassOptInRequired(CryptographyProviderApi::class)
interface MyAlgorithm : CryptographyAlgorithm {
    override val id: CryptographyAlgorithmId<MyAlgorithm> get() = Companion
    companion object : CryptographyAlgorithmId<MyAlgorithm>("MY-ALGORITHM")

    fun keyDecoder(): KeyDecoder<Key.Format, Key>
    fun keyGenerator(): KeyGenerator<Key>

    interface Key : EncodableKey<Key.Format> {
        sealed class Format : KeyFormat { ... }
        // operations: cipher(), signatureGenerator(), etc.
    }
}
```

### Encoding Formats

- **RAW**: Raw bytes only. Requires external context (algorithm, curve) to interpret.
- **DER**: ASN.1 DER encoding. Self-describing with algorithm identifier.
- **PEM**: Base64-encoded DER with header/footer labels.
- **JWK**: JSON Web Key format.

For algorithms with parameters (EC curves, DH), two decoder variants exist:

- With explicit parameters - supports all formats including RAW
- Without parameters - only DER/PEM (extracts parameters from encoding)

### API Annotations

- `@CryptographyProviderApi`: For provider implementation internals
- `@DelicateCryptographyApi`: For APIs requiring careful usage (ECB mode, etc.)
- `@SubclassOptInRequired(CryptographyProviderApi::class)`: On interfaces that providers implement

## Adding a New Algorithm

1. **Define interface** in `cryptography-core/src/commonMain/kotlin/algorithms/`
2. **Implement in providers** under each provider's `algorithms/` directory
3. **Register** in provider's `getOrNull()` method
4. **Add tests** to `build-logic/src/main/kotlin/ckbuild/tests/GenerateProviderTestsTask.kt`
5. **Create test classes** in `cryptography-provider-tests/src/commonMain/kotlin/`

## Provider Implementation

### JDK Provider

Uses object pooling for JCA objects:

```kotlin
private val keyFactory = state.keyFactory("RSA")
keyFactory.use { factory -> factory.generatePublic(spec) }
```

Base classes: `JdkPublicKeyDecoder`, `JdkPrivateKeyDecoder`, `JdkEncodableKey`

### OpenSSL Provider

Uses OpenSSL 3.x EVP API with manual memory management:

```kotlin
memScoped {
    val ctx = checkError(EVP_PKEY_CTX_new_from_name(null, "RSA", null))
    try { /* use ctx */ }
    finally { EVP_PKEY_CTX_free(ctx) }
}
```

Base classes: `Openssl3PublicKeyDecoder`, `Openssl3PrivateKeyDecoder`, `Openssl3PublicKeyEncodable`, `Openssl3PrivateKeyEncodable`

### BigInt Handling

```kotlin
val bytes = bigInt.encodeToByteArray()  // BigInt to bytes
val bigInt = bytes.decodeToBigInt()     // bytes to BigInt
```

## ASN.1 Structures

For new key/parameter encodings:

1. Define structures in `cryptography-serialization-asn1-modules`
2. Register in `KeyAlgorithmIdentifierSerializer.kt`
3. Add PEM label in `PemLabel.kt` if needed
4. Add helper functions in `cryptography-provider-base/materials/`

## Platform Limitations

| Feature      | JDK    | OpenSSL | WebCrypto | CryptoKit |
|--------------|--------|---------|-----------|-----------|
| Classical DH | Yes    | Yes     | No        | No        |
| ECDH         | Yes    | Yes     | Yes       | Yes       |
| RSA-RAW      | Yes    | Yes     | No        | No        |
| AES-ECB      | Yes    | Yes     | No        | No        |
| SHA3         | JDK 9+ | Yes     | No        | No        |

## Useful Commands

```bash
# Gradle properties
-Pckbuild.skipTestTasks=true      # Skip all test tasks
-Pckbuild.skipLinkTasks=true      # Skip native linking
-Pckbuild.warningsAsErrors=false  # Don't fail on warnings

# Update ABI declarations after adding public APIs
./gradlew :cryptography-core:updateLegacyAbi
```

## Build Logic

Custom Gradle plugins in `build-logic/`:

- `ckbuild.multiplatform-library`: Standard library setup
- `ckbuild.multiplatform-provider-tests`: Auto-generates test classes
- `ckbuild.use-openssl`: Configures OpenSSL dependencies

Target functions in `build-logic/src/main/kotlin/ckbuild/targets.kt`:

- `allTargets()`: All platforms
- `appleTargets()`: macOS, iOS, watchOS, tvOS
- `nativeTargets()`: All native platforms
- `webTargets()`: JS and WasmJS
