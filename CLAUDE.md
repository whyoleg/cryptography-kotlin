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
| Asymmetric        | RSA-OAEP, RSA-PKCS1 (sign/encrypt), RSA-PSS, RSA-RAW, ECDSA, ECDH                 |
| Key Derivation    | PBKDF2, HKDF                                                                      |

Not all algorithms are supported by all providers. Use `provider.getOrNull(algorithmId)` to check availability.

## Build Commands

```bash
# Build all modules (skip tests and native linking for faster builds)
./gradlew build -Pckbuild.skipTestTasks=true -Pckbuild.skipLinkTasks=true

# Link all native binaries
./gradlew linkAll
```

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
