# ProGuard / R8 — providers not found

JVM providers register themselves via the
Java [ServiceLoader](https://docs.oracle.com/en/java/se/17/docs/api/java.base/java/util/ServiceLoader.html)
mechanism. The provider class names are listed in `META-INF/services/` descriptor files inside the
JARs. Because no Kotlin or Java code contains a direct reference to those class names, ProGuard and
R8 treat them as unused and remove them during shrinking or obfuscation.

On Android, R8 has built-in awareness of `ServiceLoader` and keeps the registered implementations automatically.
On **desktop JVM** (e.g. Compose Desktop with ProGuard), no such built-in rules exist,
so the keep rules below must be added manually.

**Typical error:**

```
java.lang.IllegalStateException: No providers registered.
Please provide a dependency or register provider explicitly
```

---

## `keep` Rules

Create or update your ProGuard configuration file (e.g. `compose-desktop.pro`) and add the rules
for every provider you use.

```proguard
# In case `cryptography-provider-jdk` artifact is used
-keep class dev.whyoleg.cryptography.CryptographyProviderContainer
-keep class dev.whyoleg.cryptography.providers.jdk.JdkCryptographyProviderContainer
# In case `cryptography-provider-jdk-bc` artifact is used
-keep class dev.whyoleg.cryptography.providers.jdk.DefaultJdkSecurityProvider
-keep class dev.whyoleg.cryptography.providers.jdk.bc.BcDefaultJdkSecurityProvider
```

### Apply the configuration file

Point your build to the configuration file. For Compose Desktop:

```kotlin
// build.gradle.kts
compose.desktop {
    application {
        buildTypes.release.proguard {
            obfuscate = true
            configurationFiles.from(project.file("compose-desktop.pro"))
        }
    }
}
```
