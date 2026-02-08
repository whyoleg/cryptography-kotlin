# OpenSSL3

Provides implementation of [CryptographyProvider][CryptographyProvider] via [OpenSSL 3.x][OpenSSL 3.x]

For the openssl3 provider you must include two modules. You always need the api module and one additional module providing libcrypto:

* cryptography-provider-openssl3-api - provides mapping from cinterop declarations of openssl to cryptography-kotlin API.
  This module doesn't provide any configuration of how it should be linked to the `libcrypto` library. You need to combine it with exactly
  one of the following modules. Otherwise, building the final binary will fail unless correct linking arguments are provided.
* cryptography-provider-openssl3-shared - additionally provides embedded dynamic linking arguments (via cinterop) to `libcrypto`,
  so when building final binary openssl3 should be installed on PC where it builds, as well as on PC where this binary will be running.
  Embedded linking arguments use default paths, where openssl3 is installed, though if it's installed in a custom directory,
  additional configuration will be required
* cryptography-provider-openssl3-prebuilt - unlike the shared module, this module embeds `libcrypto`, so no additional setup is
  needed neither to build the final binary, nor to run it.
  Embedded OpenSSL version is 3.6.0
* cryptography-provider-openssl3-prebuilt-nativebuilds - uses libcrypto from [NativeBuilds](https://github.com/ensody/native-builds),
  so no additional setup is needed neither to build the final binary, nor to run it.
  By default, OpenSSL 3.6.0 is used.
  You can explicitly select a more recent OpenSSL version by adding a dependency on `com.ensody.nativebuilds:openssl-libcrypto:<version>`.
  This might be useful if you want to integrate security fixes as quickly as possible.

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
    implementation("dev.whyoleg.cryptography:cryptography-provider-openssl3-api:0.5.0")

    // Additionally, you must choose exactly one of these options:

    // Option 1: shared
    implementation("dev.whyoleg.cryptography:cryptography-provider-openssl3-shared:0.5.0")

    // Option 2: prebuilt
    implementation("dev.whyoleg.cryptography:cryptography-provider-openssl3-prebuilt:0.5.0")

    // Option 3: prebuilt-nativebuilds
    implementation("dev.whyoleg.cryptography:cryptography-provider-openssl3-prebuilt-nativebuilds:0.5.0")
    implementation("com.ensody.nativebuilds:openssl-libcrypto:3.6.0") // optional but recommended to get automatic (e.g. Dependabot) updates
}
```

[CryptographyProvider]: ../api/cryptography-core/dev.whyoleg.cryptography/-cryptography-provider/index.html

[OpenSSL 3.x]: https://www.openssl.org

[NativeBuilds]: https://github.com/ensody/native-builds

[Supported primitives section]: index.md#supported-primitives
