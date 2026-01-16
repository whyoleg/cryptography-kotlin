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

# Build multiple specific modules at once
./gradlew :cryptography-provider-jdk:build :cryptography-provider-openssl3-api:build -Pckbuild.skipTestTasks=true -Pckbuild.skipLinkTasks=true

# Build all modules (skip tests and native linking for faster builds)
./gradlew build -Pckbuild.skipTestTasks=true -Pckbuild.skipLinkTasks=true

# Link all native binaries
./gradlew linkAll
```

**Note:** For native targets on macOS ARM machines, only `macosArm64` tests can be run locally. Other native targets (linuxX64, mingwX64,
etc.) require their respective platforms.

## Running Tests

**In most cases, run tests for a specific provider module rather than all providers.** Each provider has its own test suite, and running all
tests across all providers is slow and usually unnecessary during development.

```bash
# Run tests for a specific provider (recommended)
./gradlew :cryptography-provider-jdk:jvmTest
./gradlew :cryptography-provider-webcrypto:jsTest
./gradlew :cryptography-provider-openssl3-prebuilt:linuxX64Test
./gradlew :cryptography-provider-cryptokit:macosArm64Test

# Run all tests for a platform (runs tests across ALL provider modules - slow)
./gradlew jvmTest
./gradlew jsTest
./gradlew wasmTest
./gradlew nativeTest
./gradlew macosTest
./gradlew iosTest
```

### Test Types

The project has three categories of tests in `cryptography-provider-tests`:

1. **Default Tests** (`default/`): Basic functionality tests for each algorithm
    - Test encryption/decryption roundtrips
    - Test key generation and encoding
    - Test various parameter combinations (key sizes, tag sizes, etc.)
    - Examples: `AesGcmTest`, `HmacTest`, `EcdsaTest`

2. **Compatibility Tests** (`compatibility/`): Cross-provider/cross-platform validation
    - `generate` step: Creates test data (keys, ciphertexts, signatures) and stores them
    - `validate` step: Loads test data from other providers/platforms and validates it
    - `loop` step: Runs generate+validate in-memory (default for local development)
    - Used to ensure cryptographic output from one provider can be read by another
    - Examples: `AesGcmCompatibilityTest`, `EcdsaCompatibilityTest`

3. **Test Vectors** (`testvectors/`): RFC/specification compliance tests
    - Tests against known-good values from RFCs and standards
    - Examples: `HkdfTestvectorsTest` (RFC 5869), `HmacTestvectorsTest`

### Running Specific Test Steps

```bash
# Run only compatibility loop tests (default - fast, in-memory)
./gradlew :cryptography-provider-jdk:jvmTest -Pckbuild.providerTests.step=compatibility.loop

# Run compatibility generate step (requires testtool server)
./gradlew :cryptography-provider-jdk:jvmTest -Pckbuild.providerTests.step=compatibility.generate -Pckbuild.testtool.enabled=true

# Run compatibility validate step
./gradlew :cryptography-provider-jdk:jvmTest -Pckbuild.providerTests.step=compatibility.validate -Pckbuild.testtool.enabled=true
```

## Architecture

### Module Structure

```
cryptography-kotlin/
├── cryptography-core/           # Public API (algorithms, operations, keys)
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
├── cryptography-bom/            # Bill of Materials
└── cryptography-version-catalog/ # Gradle version catalog
```

### Provider Selection in `optimal`

The `cryptography-provider-optimal` module auto-selects providers:

- **JVM** → JDK provider
- **JS/WasmJS** → WebCrypto provider
- **Apple** (except watchosArm32) → CryptoKit + Apple providers
- **Linux/MinGW/AndroidNative** → OpenSSL3 prebuilt

### Build Logic

Custom Gradle plugins in `build-logic/`:

- `ckbuild.multiplatform-library`: Standard library setup with JDK 8 toolchain
- `ckbuild.multiplatform-provider-tests`: Auto-generates test classes for providers
- `ckbuild.multiplatform-tests`: Base test configuration
- `ckbuild.use-openssl`: Configures OpenSSL dependencies

Target functions in `build-logic/src/main/kotlin/ckbuild/targets.kt`:

- `allTargets()`: All platforms (JVM, JS, WasmJS, WasmWasi, all native)
- `appleTargets()`: macOS, iOS, watchOS, tvOS (all architectures)
- `nativeTargets()`: All native platforms including Android Native
- `webTargets()`: JS and WasmJS
- `desktopTargets()`: Linux, MinGW, macOS

### Test Infrastructure

Provider tests use code generation. The `providerTests` extension in each provider module:

```kotlin
providerTests {
    packageName.set("dev.whyoleg.cryptography.providers.jdk")
    providerInitializers.put("JDK_Default", "CryptographyProvider.JDK")
}
```

This generates test classes that extend base tests from `cryptography-provider-tests`. The test class list is in
`build-logic/src/main/kotlin/ckbuild/tests/GenerateProviderTestsTask.kt`.

### API Annotations

- `@CryptographyProviderApi`: For provider implementation internals (not public API)
- `@DelicateCryptographyApi`: For APIs requiring careful usage (ECB mode, etc.)

Use these opt-ins when implementing providers:

```kotlin
compilerOptions {
    optIn.addAll(
        OptIns.DelicateCryptographyApi,
        OptIns.CryptographyProviderApi,
    )
}
```

## Adding a New Algorithm

1. **Define the algorithm interface** in `cryptography-core/src/commonMain/kotlin/algorithms/`:
   ```kotlin
   @SubclassOptInRequired(CryptographyProviderApi::class)
   public interface MyAlgorithm : CryptographyAlgorithm {
       override val id: CryptographyAlgorithmId<MyAlgorithm> get() = Companion
       public companion object : CryptographyAlgorithmId<MyAlgorithm>("MY-ALGORITHM")

       public fun keyDecoder(): KeyDecoder<Key.Format, Key>
       public fun keyGenerator(): KeyGenerator<Key>

       @SubclassOptInRequired(CryptographyProviderApi::class)
       public interface Key : EncodableKey<Key.Format> {
           public enum class Format : KeyFormat { RAW, JWK }
           // operations like cipher(), signatureGenerator(), etc.
       }
   }
   ```

2. **Implement in each provider** under `src/.../kotlin/algorithms/`:
    - JDK: `cryptography-provider-jdk/src/jvmMain/kotlin/algorithms/`
    - WebCrypto: `cryptography-provider-webcrypto/src/commonMain/kotlin/algorithms/`
    - OpenSSL: `cryptography-provider-openssl3-api/src/commonMain/kotlin/algorithms/`
    - Apple: `cryptography-provider-apple/src/commonMain/kotlin/algorithms/`
    - CryptoKit: `cryptography-provider-cryptokit/src/commonMain/kotlin/algorithms/`

3. **Register in provider's `getOrNull()` method**:
   ```kotlin
   override fun <A : CryptographyAlgorithm> getOrNull(identifier: CryptographyAlgorithmId<A>): A? = when (identifier) {
       // ... existing algorithms ...
       MyAlgorithm -> MyAlgorithmImpl(state)
       else -> null
   } as A?
   ```

4. **Add tests** to `build-logic/src/main/kotlin/ckbuild/tests/GenerateProviderTestsTask.kt`:
   ```kotlin
   private val testClasses = listOf(
       // ... existing tests ...
       "MyAlgorithmTest",
       "MyAlgorithmCompatibilityTest",
   )
   ```

5. **Create test classes** in `cryptography-provider-tests/src/commonMain/kotlin/`:
    - `default/MyAlgorithmTest.kt` - basic functionality tests
    - `compatibility/MyAlgorithmCompatibilityTest.kt` - cross-provider tests

## Adding a New Provider

1. Create a new module under `cryptography-providers/`
2. Apply the appropriate build plugins:
   ```kotlin
   plugins {
       id("ckbuild.multiplatform-library")
       id("ckbuild.multiplatform-provider-tests")
   }
   ```
3. Implement `CryptographyProvider`:
   ```kotlin
   @CryptographyProviderApi
   internal class MyProvider : CryptographyProvider() {
       override val name: String = "MyProvider"

       override fun <A : CryptographyAlgorithm> getOrNull(identifier: CryptographyAlgorithmId<A>): A? = when (identifier) {
           SHA256 -> MyDigest(SHA256)
           AES.GCM -> MyAesGcm()
           else -> null
       } as A?
   }
   ```
4. Register as default provider (optional) by implementing `CryptographyProviderContainer`
5. Configure `providerTests` extension for test generation

## Key Encoding Formats

Keys support multiple formats through `EncodableKey<Format>`:

- **RAW**: Raw key bytes
- **DER**: ASN.1 DER encoding
- **PEM**: PEM encoding (base64 with headers)
- **JWK**: JSON Web Key format

Use `cryptography-serialization-asn1-modules` for standard structures:

- PKCS#8 private keys
- X.509/SPKI public keys
- SEC1 EC private keys

## Useful Gradle Properties

```bash
-Pckbuild.skipTestTasks=true      # Skip all test tasks
-Pckbuild.skipLinkTasks=true      # Skip native linking
-Pckbuild.warningsAsErrors=false  # Don't fail on warnings
-Pckbuild.providerTests.step=...  # compatibility.loop|generate|validate
-Pckbuild.testtool.enabled=true   # Enable testtool server for compatibility tests
```

## ABI Management

When adding new public APIs (interfaces, classes, functions), the build will fail with ABI validation errors. Update ABI declarations:

```bash
# Update ABI for a specific module
./gradlew :cryptography-core:updateLegacyAbi
./gradlew :cryptography-provider-base:updateLegacyAbi
./gradlew :cryptography-serialization-asn1-modules:updateLegacyAbi
./gradlew :cryptography-serialization-pem:updateLegacyAbi
```

## Key Encoding Patterns

### Format Types

- **RAW**: Raw bytes of the key value only. Requires external context (algorithm parameters, curve) to interpret.
- **DER**: ASN.1 DER encoding. Self-describing - contains algorithm identifier and parameters.
- **PEM**: Base64-encoded DER with header/footer labels (e.g., `-----BEGIN PUBLIC KEY-----`).
- **JWK**: JSON Web Key format.

### Key Decoder Patterns

For algorithms with parameters (EC curves, DH parameters), there are typically two decoder variants:

```kotlin
// With explicit parameters - supports all formats including RAW
fun publicKeyDecoder(parameters: Parameters): KeyDecoder<PublicKey.Format, PublicKey>

// Without parameters - only supports DER/PEM (extracts parameters from encoding)
fun publicKeyDecoder(): KeyDecoder<PublicKey.Format, PublicKey>
```

The parameterless variant extracts parameters from the AlgorithmIdentifier in DER/PEM encodings.

## Algorithm Parameters

### Interface Pattern

Algorithm parameters (like DH p,g or EC curves) follow this pattern:

```kotlin
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface Parameters : EncodableParameters<Parameters.Format> {
    public val p: BigInt
    public val g: BigInt

    public sealed class Format : ParameterFormat {
        public data object DER : Format()
        public data object PEM : Format()
    }
}
```

### Parameter Operations

```kotlin
// Decode parameters from PEM/DER
fun parametersDecoder(): ParameterDecoder<Parameters.Format, Parameters>

// Generate new parameters (can be slow for DH)
fun parametersGenerator(primeSize: BinarySize): ParameterGenerator<Parameters>
```

### Keys Expose Parameters

Keys decoded or generated should expose their parameters:

```kotlin
public interface PublicKey : EncodableKey<PublicKey.Format> {
    public val parameters: Parameters
}
```

## Provider Implementation Patterns

### JDK Provider

Uses object pooling for JCA objects (KeyFactory, Cipher, etc.):

```kotlin
// Get pooled instance, use it, return to pool
private val keyFactory = state.keyFactory("DH")
keyFactory.use { factory -> factory.generatePublic(spec) }

// Available pooled resources
state.keyFactory(algorithm)
state.keyPairGenerator(algorithm)
state.keyAgreement(algorithm)
state.algorithmParameterGenerator(algorithm)
state.cipher(transformation)
state.signature(algorithm)
state.messageDigest(algorithm)
state.mac(algorithm)
state.secureRandom  // shared instance
```

Key decoder base classes:

- `JdkPublicKeyDecoder<KF, K>` - handles DER via X509EncodedKeySpec
- `JdkPrivateKeyDecoder<KF, K>` - handles DER via PKCS8EncodedKeySpec
- `JdkEncodableKey<KF>` - handles encoding via key.encoded

### OpenSSL Provider

Uses OpenSSL 3.x EVP API with manual memory management:

```kotlin
// Key operations use EVP_PKEY
private class MyPublicKey(
    key: CPointer<EVP_PKEY>,
) : Openssl3PublicKeyEncodable<Format>(key) {
    override fun outputType(format: Format): String = when (format) {
        Format.DER -> "DER"
        Format.PEM -> "PEM"
        Format.RAW -> error("handled explicitly")
    }
}

// Memory management pattern
memScoped {
    val ctx = checkError(EVP_PKEY_CTX_new_from_name(null, "DH", null))
    try {
        // use ctx
    } finally {
        EVP_PKEY_CTX_free(ctx)
    }
}

// Reference counting for EVP_PKEY
key.upRef()  // increment reference count
EVP_PKEY_free(key)  // decrement reference count
```

Key decoder base classes:

- `Openssl3PublicKeyDecoder<KF, K>` - uses OSSL_DECODER for DER/PEM
- `Openssl3PrivateKeyDecoder<KF, K>` - uses OSSL_DECODER for DER/PEM
- `Openssl3PublicKeyEncodable<KF>` - uses OSSL_ENCODER for DER/PEM
- `Openssl3PrivateKeyEncodable<KF, PubK>` - uses OSSL_ENCODER for DER/PEM

### BigInt Handling

```kotlin
// Convert BigInt to bytes (for OpenSSL/JDK BigInteger)
val bytes = bigInt.encodeToByteArray()

// Convert bytes to BigInt
val bigInt = bytes.decodeToBigInt()

// Strip leading zeros for unsigned representation
private fun ByteArray.trimLeadingZeros(): ByteArray {
    val firstNonZero = indexOfFirst { it != 0.toByte() }
    return when {
        firstNonZero < 0  -> byteArrayOf(0)
        firstNonZero == 0 -> this
        else              -> copyOfRange(firstNonZero, size)
    }
}
```

## ASN.1 Module Patterns

### Adding New ASN.1 Structures

1. Define structures in `cryptography-serialization-asn1-modules`:

```kotlin
// Object Identifier
public val ObjectIdentifier.Companion.DH: ObjectIdentifier
get() = ObjectIdentifier("1.2.840.113549.1.3.1")

// Algorithm Identifier for keys
public class DhKeyAlgorithmIdentifier(
    override val parameters: DhParameters?,
) : KeyAlgorithmIdentifier {
    override val algorithm: ObjectIdentifier get() = ObjectIdentifier.DH
}

// Parameter structure
@Serializable
public class DhParameters(
    public val prime: BigInt,
    public val base: BigInt,
    public val privateValueLength: Int? = null,
)
```

2. Register in `KeyAlgorithmIdentifierSerializer.kt`:

```kotlin
// Encoding
is DhKeyAlgorithmIdentifier -> encodeParameters(DhParameters.serializer(), value.parameters)

// Decoding
ObjectIdentifier.DH -> DhKeyAlgorithmIdentifier(decodeParameters(DhParameters.serializer()))
```

3. Add PEM label in `PemLabel.kt` if needed:

```kotlin
public val DhParameters: PemLabel = PemLabel("DH PARAMETERS")
```

4. Add helper functions in `cryptography-provider-base/materials/`:

```kotlin
public fun decodeDhParametersFromDer(bytes: ByteArray): Pair<BigInt, BigInt>
public fun encodeDhParametersToDer(prime: BigInt, base: BigInt): ByteArray
public fun unwrapDhParametersPem(bytes: ByteArray): ByteArray
public fun wrapDhParametersPem(derBytes: ByteArray): ByteArray
```

## Platform-Specific Limitations

| Feature      | JDK        | OpenSSL | WebCrypto | CryptoKit |
|--------------|------------|---------|-----------|-----------|
| Classical DH | ✓          | ✓       | ✗         | ✗         |
| ECDH         | ✓          | ✓       | ✓         | ✓         |
| RSA-RAW      | ✓          | ✓       | ✗         | ✗         |
| AES-ECB      | ✓          | ✓       | ✗         | ✗         |
| SHA3         | ✓ (JDK 9+) | ✓       | ✗         | ✗         |
| RIPEMD160    | ✗          | ✓       | ✗         | ✗         |

When implementing algorithms, check platform support first. Use `supportsXxx()` functions in tests to skip unsupported combinations.

## Testing Patterns

### Test Helper Functions

For algorithms with interface-based parameters, create test helpers:

```kotlin
private fun dhParameters(p: BigInt, g: BigInt): DH.Parameters = object : DH.Parameters {
    override val p: BigInt = p
    override val g: BigInt = g
    override fun encodeToByteArrayBlocking(format: DH.Parameters.Format): ByteArray {
        error("Test parameters do not support encoding")
    }
}
```

### Checking Format Support

```kotlin
@Test
fun testKeyEncodingRaw() = testWithAlgorithm {
        if (!supportsKeyFormat(MyAlgorithm.PublicKey.Format.RAW)) return@testWithAlgorithm
        // test RAW format
    }
```

### Standard Test Parameters

Use well-known test vectors (e.g., RFC 3526 MODP groups for DH) rather than generating parameters in tests - generation can be slow.
