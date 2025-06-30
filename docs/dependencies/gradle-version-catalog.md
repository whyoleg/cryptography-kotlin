# Gradle version catalog

Library provides [Gradle version catalog](https://docs.gradle.org/current/userguide/platforms.html#sec:importing-published-catalog)
which can be added to `settings.gradle.kts` to be able to add dependencies to project in type-safe way.

## Using in your projects

Configure `settings.gradle.kts`:

```kotlin
dependencyResolutionManagement {
    versionCatalogs {
        create("cryptographyLibs") {
            from("dev.whyoleg.cryptography:cryptography-version-catalog:0.4.0")
        }
    }
}
```

Use version catalog in any of `build.gradle.kts`:

```kotlin
dependencies {
    implementation(cryptographyLibs.core)
    implementation(cryptographyLibs.provider.optimal)
}
```

## Using with an existing version catalog

Paste into `libs.versions.toml`:

```toml
[versions]
cryptography = "0.4.0"

[libraries]
cryptography-core = { group = "dev.whyoleg.cryptography", name = "cryptography-core", version.ref = "cryptography" }
cryptography-provider-optimal = { group = "dev.whyoleg.cryptography", name = "cryptography-provider-optimal", version.ref = "cryptography" }
cryptography-random = { group = "dev.whyoleg.cryptography", name = "cryptography-random", version.ref = "cryptography" }
```

Use version catalog in any of `build.gradle.kts`:

```kotlin
dependencies {
    implementation(libc.cryptography.core)
    implementation(libs.cryptography.provider.optimal)
}
```
