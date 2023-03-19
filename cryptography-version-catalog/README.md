# Module cryptography-version-catalog

Provides [Gradle version catalog](https://docs.gradle.org/current/userguide/platforms.html#sec:importing-published-catalog)
which can be added to `settings.gradle.kts` to be able to add dependencies to project in type-safe way.

## Using in your projects

```kotlin
dependencyResolutionManagement {
    versionCatalogs {
        create("cryptographyLibs") {
            from("dev.whyoleg.cryptography:cryptography-version-catalog:0.1.0")
        }
    }
}
```
