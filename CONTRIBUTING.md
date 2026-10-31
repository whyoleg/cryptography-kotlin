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
├── cryptography-testhost/       # Test platform APIs: environment, test storage
├── cryptography-tests/          # Provider tests framework and algorithm tests
├── cryptography-providers/
│   ├── base/                    # Shared provider utilities
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
│   ├── teststorage/             # Test storage directory and HTTP server for JS/Android tests
│   └── provider-tests/          # Provider tests generation, filters and limitations snapshot
├── limitations.json             # Snapshot of provider limitations, observed in tests
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

Run tests for a specific provider rather than all providers, optionally only for a specific algorithm
(converted to a test class pattern, f.e. `aes-gcm` -> `*AesGcm*`):

```bash
just test-provider jdk
just test-provider jdk aes-gcm
```

| Provider           | `just test-provider` | Notes          |
|--------------------|----------------------|----------------|
| JDK                | `jdk`                |                |
| JDK + BouncyCastle | `jdk-bc`             |                |
| WebCrypto (WasmJS) | `webcrypto`          | Node.js        |
| Apple CommonCrypto | `apple`              | Requires macOS |
| CryptoKit          | `cryptokit`          | Requires macOS |
| OpenSSL3 Prebuilt  | `openssl3`           | macOS ARM      |

Every provider test generates data (keys, ciphertexts, signatures, etc.), validates it and stores it in the test storage
(`build/test-storage/`), together with a report of the test and its environment.
On JVM and native, tests access the storage directly, on JS and Android – via an HTTP server, started automatically.

After the build, generated test data is deleted, unless some task failed (to investigate failures) or `--keep` is passed.
Reports are always kept, as they are used to update [limitations](#limitations).

### Compatibility Tests

The `restore` test of every algorithm validates *all* data in the test storage, so data generated by one provider
(or platform) is validated by other providers. Steps (`--step`):

- `generate` (default) – all tests, except `restore`
- `restore` – only `restore` tests

```bash
# 1. Clean previous test storage (start fresh)
just compat-clean

# 2. Generate data for each provider you want to test, keeping it
just test-provider jdk --keep
just test-provider cryptokit --keep

# 3. Validate all data with each provider
just test-provider jdk --step restore
just test-provider cryptokit --step restore
```

Skip `compat-clean` only when intentionally adding more providers on top of an existing generate run.
To test a specific algorithm, pass it to every command, f.e. `just test-provider jdk aes-gcm --keep`.

### Test Structure

Tests are organized in `cryptography-tests` (package `dev.whyoleg.cryptography.tests`):

| Directory     | Purpose                                                                                     |
|---------------|---------------------------------------------------------------------------------------------|
| `algorithms/` | Test suite per algorithm: random data generation, RFC/specification test vectors, `restore` |
| `operations/` | Validators of data per operation (ciphers, signatures, digests, key encoding, etc.)         |
| root          | Test framework: runner, test storage, limitations                                           |

Test classes are generated for each provider by `GenerateProviderTestsTask` in `build-logic/provider-tests`.

### Limitations

Unsupported algorithms and operations are declared in tests via `fails`/`lenient`/`skip` limitations,
with descriptions which are shown in the documentation, so they must be user-facing and self-contained.

Limitations observed in test runs (reports in the test storage) are stored in `limitations.json`, which is used
to generate provider support tables in the documentation. To update it after running tests:

```bash
./gradlew updateTestLimitations
```

Only environments present in the test storage are updated. CI checks that `limitations.json` matches limitations
observed in all CI environments and uploads an updated file as the `limitations` artifact on mismatch.

### Platform Limitations

- On macOS ARM machines, only `macosArm64` tests can be run locally
- `linuxX64`, `mingwX64`, etc. require their respective platforms
- Use CI for full cross-platform testing

Provider limitations are described in tests and observed in `limitations.json`, see [Limitations](#limitations).

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

1. Create a test suite in `cryptography-tests/src/commonMain/kotlin/algorithms/` (see similar algorithms):
    - `random` test, generating data for generated keys
    - test vectors from RFCs/specifications (if available)
    - limitations of providers, which don't support the algorithm or some of its operations
2. Register it in `build-logic/provider-tests/src/main/kotlin/GenerateProviderTestsTask.kt`
3. Add a row for it in `build-logic/src/main/kotlin/ckbuild/docs/GenerateAlgorithmTablesTask.kt`
4. Run tests for all providers and update `limitations.json`

### 5. Update Public API

```bash
just update-abi
```

## CI/CD

GitHub Actions runs on PRs and pushes:

- Build validation across all platforms
- Tests on Linux, macOS, Windows
- Android emulator tests
- Default tests: all tests, except provider tests (`-Pckbuild.skipProviderTestTasks=true`)
- Provider tests (`run-tests-compatibility.yml`): data generated on all platforms is validated on all platforms,
  and `limitations.json` must match limitations observed in tests

Check workflow results in the Actions tab before merging.

## Documentation

- Update `docs/` when adding user-facing features
- API documentation is auto-generated via Dokka

```bash
just docs
```
