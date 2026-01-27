# Contributing to cryptography-kotlin

This guide covers development setup, building, testing, and contribution workflow.

## Prerequisites

- JDK 17+ (for building)
- Gradle 8.x (wrapper included)
- For native development on macOS: Xcode Command Line Tools

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

## Building

### Build Specific Modules (Recommended)

Building specific modules is faster than building everything:

```bash
# Build a provider module
./gradlew :cryptography-provider-jdk:build -Pckbuild.skipTestTasks=true -Pckbuild.skipLinkTasks=true

# Build core API
./gradlew :cryptography-core:build -Pckbuild.skipTestTasks=true -Pckbuild.skipLinkTasks=true

# Build OpenSSL API
./gradlew :cryptography-provider-openssl3-api:build -Pckbuild.skipTestTasks=true -Pckbuild.skipLinkTasks=true
```

### Build All Modules

```bash
# Skip tests and native linking for faster builds
./gradlew build -Pckbuild.skipTestTasks=true -Pckbuild.skipLinkTasks=true

# Link all native binaries
./gradlew linkAll
```

### Gradle Properties

| Property                           | Description            |
|------------------------------------|------------------------|
| `-Pckbuild.skipTestTasks=true`     | Skip all test tasks    |
| `-Pckbuild.skipLinkTasks=true`     | Skip native linking    |
| `-Pckbuild.warningsAsErrors=false` | Don't fail on warnings |

## Running Tests

### Provider Tests (Recommended)

Run tests for a specific provider rather than all providers:

```bash
# JVM tests
./gradlew :cryptography-provider-jdk:jvmTest

# JavaScript tests
./gradlew :cryptography-provider-webcrypto:jsTest

# Native tests (macOS ARM)
./gradlew :cryptography-provider-openssl3-prebuilt:macosArm64Test
./gradlew :cryptography-provider-cryptokit:macosArm64Test

# Specific test class
./gradlew :cryptography-provider-jdk:jvmTest --tests "dev.whyoleg.cryptography.providers.jdk.JDK_Default_AesGcmTest"
```

### Test Types

Tests are organized in `cryptography-provider-tests`:

| Type          | Directory        | Purpose                                                         |
|---------------|------------------|-----------------------------------------------------------------|
| Default       | `default/`       | Basic functionality tests (encryption roundtrips, key encoding) |
| Compatibility | `compatibility/` | Cross-provider/cross-platform validation                        |
| Test Vectors  | `testvectors/`   | RFC/specification compliance tests                              |

### Test Filtering (Compatibility Tests)

```bash
# Run all compatibility steps
./gradlew allTest -Pckbuild.providerTests.step=compatibility.loop

# Run specific step
./gradlew allTest -Pckbuild.providerTests.step=compatibility.generate
./gradlew allTest -Pckbuild.providerTests.step=compatibility.generateStress
./gradlew allTest -Pckbuild.providerTests.step=compatibility.validate
```

### Platform Limitations

- On macOS ARM machines, only `macosArm64` tests can be run locally
- `linuxX64`, `mingwX64`, etc. require their respective platforms
- Use CI for full cross-platform testing

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
2. Create test classes in `cryptography-provider-tests/src/commonMain/kotlin/`:
    - Default test in `default/`
    - Compatibility test in `compatibility/`
    - Test vectors in `testvectors/` (if available)

### 5. Update Public API

```bash
./gradlew :cryptography-core:updateLegacyAbi
```

## Build Logic

Custom Gradle plugins in `build-logic/`:

| Plugin                                 | Purpose                         |
|----------------------------------------|---------------------------------|
| `ckbuild.multiplatform-library`        | Standard library setup          |
| `ckbuild.multiplatform-provider-tests` | Auto-generates test classes     |
| `ckbuild.use-openssl`                  | Configures OpenSSL dependencies |

Target functions in `build-logic/src/main/kotlin/ckbuild/targets.kt`:

| Function          | Targets                   |
|-------------------|---------------------------|
| `allTargets()`    | All platforms             |
| `appleTargets()`  | macOS, iOS, watchOS, tvOS |
| `nativeTargets()` | All native platforms      |
| `webTargets()`    | JS and WasmJS             |

## Code Style

- Follow default Kotlin IDEA formatting
- Copyright header: `Copyright (c) <current-year> Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.`

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
# Generate API docs
./gradlew dokkaGeneratePublicationHtml

# Build documentation site
./gradlew mkdocsBuild
```
