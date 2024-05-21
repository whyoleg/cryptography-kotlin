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
