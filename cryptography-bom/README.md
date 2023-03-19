# Module cryptography-bom

Provides [Maven BOM](https://docs.gradle.org/current/userguide/platforms.html#sub:bom_import).
Additionally, Gradle will
automatically [align dependencies](https://docs.gradle.org/current/userguide/dependency_version_alignment.html#aligning_versions_natively_with_gradle)
of all modules because of direct dependency on BOM module.

## Using in your projects

```kotlin
dependencies {
    implementation(platform("dev.whyoleg.cryptography:cryptography-bom:0.1.0"))

    // now you can declare other dependencies without version 
    implementation("dev.whyoleg.cryptography:cryptography-core")
}
```
