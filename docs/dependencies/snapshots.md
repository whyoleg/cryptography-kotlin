# Snapshots

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
