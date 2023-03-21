# Overview

cryptography-kotlin library provides both common multi-platform API for cryptography operations and several providers implementing API.

## Using in your projects

Make sure that you use Kotlin 1.8.10+.
Additionally, it's possible to use [BOM](bom.md) or [Gradle version catalog](gradle-version-catalog.md) to add dependencies easier

> ⚠️ NOT YET PUBLISHED TO MAVEN CENTRAL

```kotlin
repositories {
    mavenCentral()
}
dependencies {
    implementation("dev.whyoleg.cryptography:cryptography-core:0.1.0")
    // some provider
    implementation("dev.whyoleg.cryptography:cryptography-jdk:0.1.0")
}
```

<details>
<summary>Snapshots of the development version are available in Sonatype's snapshot repository.</summary>
<p>

```kotlin
repositories {
    maven("https://s01.oss.sonatype.org/content/repositories/snapshots/")
}
dependencies {
    implementation("dev.whyoleg.cryptography:cryptography-core:0.1.0-SNAPSHOT")
    // some provider
    implementation("dev.whyoleg.cryptography:cryptography-jdk:0.1.0-SNAPSHOT")
}
```

</p>
</details>

## Bugs and Feedback

For bugs, questions and discussions, please use the [GitHub Issues](https://github.com/whyoleg/cryptography-kotlin/issues).

## License

    Copyright 2023 Oleg Yukhnevich.

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
