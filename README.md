# cryptography-kotlin

Types-safe Multiplatform cryptography library for Kotlin

```kotlin
CryptographyProvider.Default
    .get(SHA512)
    .hasher()
    .hash("Kotlin is Awesome".encodeToByteArray())
```

## Modules

* `cryptography-random` - zero-dependency platform-dependent CSPRNG
* `cryptography-core`
    * operations
    * algorithms
    * materials
    * provider
* providers:
    * `cryptography-jdk` - uses JCE: javax.crypto.* and java.security.* (TODO link)
    * `cryptography-webcrypto` - uses WebCrypto (TODO link)
    * `cryptography-apple` - uses CoreCrypto/CommonCrypto` (TODO link)
    * `cryptography-openssl3` - uses OpenSSL 3.x (TODO link)
        * `cryptography-openssl3-dynamic` - dynamically linked
        * `cryptography-openssl3-static` - statically linked to prebuilt OpenSSL 3.0.7
* `cryptography-bom`

## Usage

> ⚠️ NOT YET PUBLISHED TO MAVEN CENTRAL

```kotlin
repositories {
    mavenCentral()
}
dependencies {
    implementation("dev.whyoleg.cryptography:cryptography-core:0.1.0")
    implementation("dev.whyoleg.cryptography:cryptography-PROVIDER_NAME:0.1.0")
}
```

<details>
<summary>Snapshots of the development version are available in Sonatype's snapshots repository.</summary>
<p>

```kotlin
repositories {
    maven("https://s01.oss.sonatype.org/content/repositories/snapshots/")
}
dependencies {
    implementation("dev.whyoleg.cryptography:cryptography-core:0.1.0-SNAPSHOT")
    implementation("dev.whyoleg.cryptography:cryptography-PROVIDER_NAME:0.1.0-SNAPSHOT")
}
```

</p>
</details>

## Supported targets per provider

> Provider artifacts are `cryptography-NAME` (e.g. `cryptography-openssl3`)

| target                                    | jdk | webcrypto | apple | openssl3      |
|-------------------------------------------|-----|-----------|-------|---------------|
| jvm                                       | ✅   | ➖         | ➖     | ❌             |
| js                                        | ➖   | ✅         | ➖     | ❌             |
| iosX64<br/>iosSimulatorArm64<br/>iosArm64 | ➖   | ➖         | ✅     | ✅ only static |
| tvOS<br/>watchOS                          | ➖   | ➖         | ✅     | ❌             |
| macosX64<br/>macosArm64                   | ➖   | ➖         | ✅     | ✅             |
| linuxX64                                  | ➖   | ➖         | ➖     | ✅             |
| mingwX64                                  | ➖   | ➖         | ➖     | ✅             |

## Supported algorithms per provider

> Provider artifacts are `cryptography-NAME` (e.g. `cryptography-openssl3`)

| Operation                                   | Algorithm   | jdk | webcrypto | apple | openssl3 |
|---------------------------------------------|-------------|:---:|:---------:|:-----:|:--------:|
| **Digest**                                  | ⚠️ MD5      |  ✅  |     ❌     |   ✅   |    ✅     |
|                                             | ⚠️ SHA1     |  ✅  |     ✅     |   ✅   |    ✅     |
|                                             | SHA256      |  ✅  |     ✅     |   ✅   |    ✅     |
|                                             | SHA384      |  ✅  |     ✅     |   ✅   |    ✅     |
|                                             | SHA512      |  ✅  |     ✅     |   ✅   |    ✅     |
| **MAC**                                     | HMAC        |  ✅  |     ✅     |   ✅   |    ✅     |
| **Symmetric-key<br/>encryption/decryption** | AES-CBC     |  ✅  |     ✅     |   ✅   |    ✅     |
|                                             | AES-GCM     |  ✅  |     ✅     |   ❌   |    ✅     |
| **Public-key<br/>encryption/decryption**    | RSA-OAEP    |  ✅  |     ✅     |   ❌   |    ✅     |
| **Digital Signatures**                      | ECDSA       |  ✅  |     ✅     |   ❌   |    ✅     |
|                                             | RSA-SSA-PSS |  ✅  |     ✅     |   ❌   |    ✅     |
