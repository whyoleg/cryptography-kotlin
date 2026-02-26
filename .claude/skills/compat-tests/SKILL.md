---
name: compat-tests
description: Run cross-provider compatibility tests for specific algorithms and providers in the cryptography-kotlin project. Use this skill when the user asks to run compatibility tests, cross-provider validation, or wants to verify that a specific algorithm (like AES-GCM, ECDSA, HMAC, etc.) produces consistent results across different providers (JDK, OpenSSL3, Apple, CryptoKit, WebCrypto). Also use when the user mentions "generate and validate" test data, or references the compatibility test pipeline.
---

# Compatibility Test Runner

Run cross-provider compatibility tests for specific algorithms and providers. The compatibility pipeline has two sequential phases:

1. **Generate** - Each provider creates test vectors (keys, ciphertexts, signatures, etc.) and stores them via the testtool server
2. **Validate** - Each provider reads ALL generated test vectors and verifies them, ensuring cross-provider compatibility

## Workflow

1. **Clean server storage** (default) - Remove stale data from previous runs
2. **Run generate** for all requested providers (can be a single Gradle invocation)
3. **Run validate** for all requested providers (can be a single Gradle invocation)

### Step 1: Clean server storage

```bash
rm -rf build/testtool/server-storage
```

Skip this only if the user explicitly wants to keep existing data (e.g., generating for additional providers on top of a previous run).

### Step 2: Run generate

```bash
./gradlew <module:task> [<module:task> ...] \
  --continue \
  -Pckbuild.providerTests.step=compatibility.generate \
  -Pckbuild.testtool.enabled=true \
  --tests "*<AlgorithmCompatibilityTest>*"
```

### Step 3: Run validate

```bash
./gradlew <module:task> [<module:task> ...] \
  --continue \
  -Pckbuild.providerTests.step=compatibility.validate \
  -Pckbuild.testtool.enabled=true \
  --tests "*<AlgorithmCompatibilityTest>*"
```

Multiple provider modules can be combined in a single Gradle invocation by listing multiple `module:task` pairs. The `--continue` flag
ensures all providers run even if one fails.

To run ALL compatibility tests (not filtered by algorithm), omit the `--tests` flag.

## Provider Reference

| Provider          | Module                                     | Test Task        | Notes          |
|-------------------|--------------------------------------------|------------------|----------------|
| JDK               | `:cryptography-provider-jdk`               | `jvmTest`        |                |
| Apple             | `:cryptography-provider-apple`             | `macosArm64Test` | Requires macOS |
| CryptoKit         | `:cryptography-provider-cryptokit`         | `macosArm64Test` | Requires macOS |
| OpenSSL3 Shared   | `:cryptography-provider-openssl3-shared`   | `macosArm64Test` |                |
| OpenSSL3 Prebuilt | `:cryptography-provider-openssl3-prebuilt` | `macosArm64Test` |                |
| WebCrypto (JS)    | `:cryptography-provider-webcrypto`         | `jsNodeTest`     |                |
| WebCrypto (Wasm)  | `:cryptography-provider-webcrypto`         | `wasmJsNodeTest` |                |

## Algorithm to Test Class Mapping

Use the test class name in the `--tests` filter.

| Algorithm         | Test Class                          |
|-------------------|-------------------------------------|
| AES-GCM           | `AesGcmCompatibilityTest`           |
| AES-CCM           | `AesCcmCompatibilityTest`           |
| AES-CBC           | `AesCbcCompatibilityTest`           |
| AES-CTR           | `AesCtrCompatibilityTest`           |
| AES-CFB           | `AesCfbCompatibilityTest`           |
| AES-CFB8          | `AesCfb8CompatibilityTest`          |
| AES-OFB           | `AesOfbCompatibilityTest`           |
| AES-ECB           | `AesEcbCompatibilityTest`           |
| AES-CMAC          | `AesCmacCompatibilityTest`          |
| ChaCha20-Poly1305 | `ChaCha20Poly1305CompatibilityTest` |
| HMAC              | `HmacCompatibilityTest`             |
| ECDSA             | `EcdsaCompatibilityTest`            |
| ECDH              | `EcdhCompatibilityTest`             |
| EdDSA             | `EdDsaCompatibilityTest`            |
| XDH               | `XdhCompatibilityTest`              |
| DH                | `DhCompatibilityTest`               |
| RSA-OAEP          | `RsaOaepCompatibilityTest`          |
| RSA-PKCS1         | `RsaPkcs1CompatibilityTest`         |
| RSA-PKCS1-ES      | `RsaPkcs1EsCompatibilityTest`       |
| RSA-PSS           | `RsaPssCompatibilityTest`           |
| RSA-RAW           | `RsaRawCompatibilityTest`           |
| PBKDF2            | `Pbkdf2CompatibilityTest`           |
| HKDF              | `HkdfCompatibilityTest`             |
| MD5               | `Md5CompatibilityTest`              |
| SHA-1             | `Sha1CompatibilityTest`             |
| SHA-224           | `Sha224CompatibilityTest`           |
| SHA-256           | `Sha256CompatibilityTest`           |
| SHA-384           | `Sha384CompatibilityTest`           |
| SHA-512           | `Sha512CompatibilityTest`           |
| SHA3-224          | `Sha3B224CompatibilityTest`         |
| SHA3-256          | `Sha3B256CompatibilityTest`         |
| SHA3-384          | `Sha3B384CompatibilityTest`         |
| SHA3-512          | `Sha3B512CompatibilityTest`         |
| RIPEMD-160        | `Ripemd160CompatibilityTest`        |

## Example: AES-CCM on JDK + CryptoKit (macOS)

```bash
# 1. Clean
rm -rf build/testtool/server-storage

# 2. Generate for both providers
./gradlew \
  :cryptography-provider-jdk:jvmTest \
  :cryptography-provider-cryptokit:macosArm64Test \
  --continue \
  -Pckbuild.providerTests.step=compatibility.generate \
  -Pckbuild.testtool.enabled=true \
  --tests "*AesCcmCompatibilityTest*"

# 3. Validate for both providers
./gradlew \
  :cryptography-provider-jdk:jvmTest \
  :cryptography-provider-cryptokit:macosArm64Test \
  --continue \
  -Pckbuild.providerTests.step=compatibility.validate \
  -Pckbuild.testtool.enabled=true \
  --tests "*AesCcmCompatibilityTest*"
```

## Common Shorthand

When the user says a provider name, map it as follows:

| User says             | Provider(s) to use                              |
|-----------------------|-------------------------------------------------|
| "jdk"                 | JDK                                             |
| "apple"               | Apple                                           |
| "cryptokit"           | CryptoKit                                       |
| "webcrypto", "js"     | WebCrypto (JS)                                  |
| "wasm"                | WebCrypto (Wasm)                                |
| "openssl", "openssl3" | OpenSSL3 Prebuilt                               |
| "openssl shared"      | OpenSSL3 Shared                                 |
| "all local"           | All providers available on the current platform |

## Notes

- The testtool server starts automatically when `-Pckbuild.testtool.enabled=true` is set - no manual server management needed
- Server storage persists in `build/testtool/server-storage/` between Gradle invocations within the same generate/validate cycle
- Not all algorithms are supported by all providers. If a provider doesn't support an algorithm, the test will be skipped (not fail)
- The `--continue` flag is important: it ensures all requested providers run even if one encounters a failure
