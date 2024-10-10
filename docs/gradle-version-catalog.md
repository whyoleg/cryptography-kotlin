# Gradle version catalog

Library provides [Gradle version catalog](https://docs.gradle.org/current/userguide/platforms.html#sec:importing-published-catalog)
which can be added to `settings.gradle.kts` to be able to add dependencies to project in type-safe way.

## Using in your projects

Configure `settings.gradle.kts`:

```kotlin
dependencyResolutionManagement {
    versionCatalogs {
        create("cryptographyLibs") {
            from("dev.whyoleg.cryptography:cryptography-version-catalog:0.3.1")
        }
    }
}
```

Use version catalog in any of `build.gradle.kts`:

```kotlin
dependencies {
    implementation(cryptographyLibs.core)
    // some provider
    implementation(cryptographyLibs.provider.jdk)
}
```

## Using with an existing version catalog

Paste into `libs.versions.toml`:

```toml
[versions]
cryptography = "0.3.1"

[libraries]
cryptography-core = { group = "dev.whyoleg.cryptography", name = "cryptography-core", version.ref = "cryptography" }
cryptography-provider-apple = { group = "dev.whyoleg.cryptography", name = "cryptography-provider-apple", version.ref = "cryptography" }
cryptography-provider-jdk = { group = "dev.whyoleg.cryptography", name = "cryptography-provider-jdk", version.ref = "cryptography" }
cryptography-provider-openssl3-prebuilt = { group = "dev.whyoleg.cryptography", name = "cryptography-provider-openssl3-prebuilt", version.ref = "cryptography" }
cryptography-provider-webcrypto = { group = "dev.whyoleg.cryptography", name = "cryptography-provider-webcrypto", version.ref = "cryptography" }
cryptography-random = { group = "dev.whyoleg.cryptography", name = "cryptography-random", version.ref = "cryptography" }
```

Use version catalog in any of `build.gradle.kts`:

```kotlin
dependencies {
    implementation(libc.cryptography.core)
    // some provider
    implementation(libs.cryptography.provider.jdk)
}
```
