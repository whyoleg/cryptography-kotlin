# Module cryptography-provider-openssl3

Provides implementation of [CryptographyProvider][CryptographyProvider] via [OpenSSL 3.x][OpenSSL 3.x]

There are overall 3 modules which provide openssl3 provider:

* cryptography-provider-openssl3-api - provides mapping from cinterop declarations of openssl to cryptography-kotlin API.
  Module doesn't provide any configuration of how it should be linked to `libcrypto` library, and so building final binary will fail
  unless correct linking arguments will be provided
* cryptography-provider-openssl3-shared - additionally provides embedded dynamic linking arguments (via cinterop) to `libcrypto`,
  so when building final binary openssl3 should be installed on PC where it builds, as well as on PC where this binary will be running.
  Embedded linking arguments use default paths, where openssl3 is installed, though if it's installed in a custom directory,
  additional configuration will be required
* cryptography-provider-openssl3-prebuilt - unlike shared module, this module embed `libcrypto` inside module, so no additional setup is
  needed
  not to build final binary, not to run it

For supported targets and algorithms, please consult [Supported primitives section][Supported primitives section]

## Limitations

* KeyFormat: doesn't support `JWK` key format yet

## Example

```kotlin
val provider = CryptographyProvider.Openssl3 // or CryptographyProvider.Default

// get some algorithm
provider.get(SHA512)
```

## Using in your projects

```kotlin
dependencies {
    implementation("dev.whyoleg.cryptography:cryptography-provider-openssl3-api:0.2.0")
    // or
    implementation("dev.whyoleg.cryptography:cryptography-provider-openssl3-shared:0.2.0")
    // or
    implementation("dev.whyoleg.cryptography:cryptography-provider-openssl3-prebuilt:0.2.0")
}
```

[CryptographyProvider]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography/-cryptography-provider/index.html

[OpenSSL 3.x]: https://www.openssl.org

[Supported primitives section]: https://whyoleg.github.io/cryptography-kotlin/providers#supported-primitives

# Package dev.whyoleg.cryptography.providers.openssl3

Provides implementation of [CryptographyProvider][CryptographyProvider] via [OpenSSL 3.x](https://www.openssl.org).

[CryptographyProvider]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography/-cryptography-provider/index.html

[OpenSSL 3.x]: https://www.openssl.org

[Supported primitives section]: https://whyoleg.github.io/cryptography-kotlin/providers#supported-primitives
