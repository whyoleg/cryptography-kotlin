# CLAUDE.md

Guidance for Claude Code when working with this repository.

## Quick Reference

- **Build**: `./gradlew :module-name:build -Pckbuild.skipTestTasks=true -Pckbuild.skipLinkTasks=true`
- **Test**: `./gradlew :cryptography-provider-jdk:jvmTest`
- **Full commands**: See [CONTRIBUTING.md](CONTRIBUTING.md)

## Project Overview

cryptography-kotlin is a type-safe Multiplatform cryptography library for Kotlin. It does NOT implement algorithms itself but wraps
platform-specific implementations:

| Provider           | Platforms                         |
|--------------------|-----------------------------------|
| OpenSSL 3.x        | Linux, MinGW, Android Native      |
| WebCrypto          | JS, WasmJS (browser/Node.js)      |
| CryptoKit          | Apple (macOS, iOS, watchOS, tvOS) |
| Apple CommonCrypto | Apple (legacy algorithms)         |
| JCA                | JVM, Android                      |

The library provides **uniform behavior** across platforms - same code produces same results regardless of provider.

## Decision-Making Priorities

When implementing features, prioritize in this order:

1. **API consistency** - Follow existing patterns exactly
2. **Completeness** - Implement for all applicable providers
3. **Performance** - Optimize where it matters
4. **Simplicity** - Keep code simple, but not at the cost of above

## Workflow for Changes

1. **Explore** - Understand existing code, look at similar algorithms/APIs
2. **Plan** - Design the approach before implementing
3. **Implement** - Follow existing patterns
4. **Test** - All test types required for new algorithms
5. **Document** - Update `docs/` if user-facing
6. **Do not commit** - Leave commits to the user

## Keeping Documentation Updated

When you discover new information during a session, proactively update the relevant documentation:

| Discovery                         | Update            |
|-----------------------------------|-------------------|
| New pattern or convention         | `CLAUDE.md`       |
| Build/test command or workflow    | `CONTRIBUTING.md` |
| User-facing feature or API        | `docs/`           |
| Provider limitation or capability | `docs/providers/` |

**Examples of when to update:**

- Found a non-obvious gotcha or pitfall → add to CLAUDE.md
- Learned a new Gradle property or command → add to CONTRIBUTING.md
- Clarified algorithm support on a provider → update docs/providers/
- User corrected a misunderstanding → fix the relevant doc

Ask before making documentation changes if unsure whether the information is project-specific or session-specific.

## Critical Patterns

### Algorithm Interface Pattern

All algorithms follow this exact structure:

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
    }
}
```

### Provider Implementation Pattern

```kotlin
// In provider's algorithms/ directory
internal class ProviderMyAlgorithm(private val state: ProviderState) : MyAlgorithm {
    override fun keyDecoder(): KeyDecoder<...> = ...
    override fun keyGenerator(...): KeyGenerator<...> = ...
}

// Register in provider's getOrNull()
MyAlgorithm -> ProviderMyAlgorithm(state)
```

### Deprecation Handling

When deprecating APIs:

- Use `@Deprecated` with `DeprecationLevel.ERROR`
- Throw exception if implementation is not feasible
- Never silently ignore deprecated behavior

## Platform-Specific Code

### Key Rules

1. **Try to implement everywhere** - Document clearly if a feature can't be supported on a platform
2. **Use `getOrNull()`** - Not all algorithms are available on all providers
3. **Test on available platforms** - On macOS ARM, only `macosArm64` tests run locally

### Target Differences to Watch

| Issue                   | Platforms Affected                             |
|-------------------------|------------------------------------------------|
| Native linking          | All native targets need explicit linking       |
| WebCrypto limitations   | Many algorithms unsupported (SHA3, CMAC, etc.) |
| CryptoKit limitations   | No AES-CBC, AES-CTR, RSA encryption            |
| JDK version differences | Algorithms vary by Java version                |

## Test Requirements

For new algorithms, **all test types are required**:

| Test Type     | Location               | Purpose                   |
|---------------|------------------------|---------------------------|
| Default       | `tests/default/`       | Basic functionality       |
| Compatibility | `tests/compatibility/` | Cross-provider validation |
| Test Vectors  | `tests/testvectors/`   | RFC compliance            |

Tests are written **after** the algorithm API is defined. Implementations can be added incrementally.

## API Annotations

| Annotation                                               | Usage                                      |
|----------------------------------------------------------|--------------------------------------------|
| `@CryptographyProviderApi`                               | Provider implementation internals          |
| `@DelicateCryptographyApi`                               | Dangerous APIs (ECB, MD5, SHA1, RIPEMD160) |
| `@SubclassOptInRequired(CryptographyProviderApi::class)` | Interfaces for provider implementation     |

## Naming Conventions

| Element                  | Pattern                                                    | Example                      |
|--------------------------|------------------------------------------------------------|------------------------------|
| Provider algorithm class | `<Provider><Algorithm>`                                    | `JdkAesGcm`, `Openssl3Ecdsa` |
| Provider key class       | `<Provider><Algorithm>Key`                                 | `JdkAesGcmKey`               |
| Package                  | `dev.whyoleg.cryptography.providers.<provider>.algorithms` |                              |
| Test class (generated)   | `<Provider>_<TestType>_<Algorithm>Test`                    | `JDK_Default_AesGcmTest`     |

## Files to Never Modify

- Binary files (`.so`, `.dylib`, `.dll`, prebuilt libraries)
- Generated files in `build/` directories

## Module Quick Reference

| Module                         | Purpose                    |
|--------------------------------|----------------------------|
| `cryptography-core`            | Public API definitions     |
| `cryptography-provider-base`   | Shared provider utilities  |
| `cryptography-provider-{name}` | Provider implementations   |
| `cryptography-provider-tests`  | Shared test infrastructure |
| `cryptography-serialization-*` | PEM/ASN.1 encoding         |

## Links

- [CONTRIBUTING.md](CONTRIBUTING.md) - Build commands, test commands, development workflow
- [docs/](docs/) - Library documentation
- [docs/providers/](docs/providers/) - Provider-specific documentation and support matrices
