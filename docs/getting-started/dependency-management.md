# Dependency Management

## Gradle version catalog

The library provides a [Gradle version catalog](https://docs.gradle.org/current/userguide/platforms.html#sec:importing-published-catalog)
which can be added to `settings.gradle.kts` to be able to add dependencies to project in type-safe way.

Configure `settings.gradle.kts`:

```kotlin
dependencyResolutionManagement {
    versionCatalogs {
        create("cryptographyLibs") {
            from("dev.whyoleg.cryptography:cryptography-version-catalog:0.5.0")
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

### Using with an existing version catalog

Paste into `libs.versions.toml`:

```toml
[versions]
cryptography = "0.5.0"

[libraries]
cryptography-core = { group = "dev.whyoleg.cryptography", name = "cryptography-core", version.ref = "cryptography" }
cryptography-provider-optimal = { group = "dev.whyoleg.cryptography", name = "cryptography-provider-optimal", version.ref = "cryptography" }
```

Use version catalog in any of `build.gradle.kts`:

```kotlin
dependencies {
    implementation(libs.cryptography.core)
    implementation(libs.cryptography.provider.optimal)
}
```

## BOM

The library provides a [Maven BOM](https://docs.gradle.org/current/userguide/platforms.html#sub:bom_import)
which could simplify adding dependencies by allowing omitting versions.
Additionally, Gradle will
automatically [align dependencies](https://docs.gradle.org/current/userguide/dependency_version_alignment.html#aligning_versions_natively_with_gradle)
of all modules because of direct dependency on the BOM module.

```kotlin
dependencies {
    implementation(platform("dev.whyoleg.cryptography:cryptography-bom:0.5.0"))

    // now you can declare other dependencies without a version
    implementation("dev.whyoleg.cryptography:cryptography-core")
    implementation("dev.whyoleg.cryptography:cryptography-provider-optimal")
}
```

## Snapshots

Snapshots of the development version are available in Sonatype's snapshot repository:

```kotlin
repositories {
    maven("https://central.sonatype.com/repository/maven-snapshots/") {
        content {
            includeGroup("dev.whyoleg.cryptography")
        }
    }
}

// it's still possible to use BOM or version catalog if needed
kotlin {
    sourceSets {
        commonMain.dependencies {
            implementation("dev.whyoleg.cryptography:cryptography-core:0.6.0-SNAPSHOT")
            implementation("dev.whyoleg.cryptography:cryptography-provider-optimal:0.6.0-SNAPSHOT")
        }
    }
}
```
