# BOM

Library provides [Maven BOM](https://docs.gradle.org/current/userguide/platforms.html#sub:bom_import)
which could simplify adding dependencies by allowing omitting versions.
Additionally, Gradle will
automatically [align dependencies](https://docs.gradle.org/current/userguide/dependency_version_alignment.html#aligning_versions_natively_with_gradle)
of all modules because of direct dependency on the BOM module

## Using in your projects

```kotlin
dependencies {
    implementation(platform("dev.whyoleg.cryptography:cryptography-bom:0.3.1"))

    // now you can declare other dependencies without a version 
    implementation("dev.whyoleg.cryptography:cryptography-core")
    // some provider
    implementation("dev.whyoleg.cryptography:cryptography-provider-jdk")
}
```
