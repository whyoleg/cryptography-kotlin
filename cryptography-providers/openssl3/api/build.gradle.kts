import org.jetbrains.kotlin.gradle.plugin.mpp.*
import org.jetbrains.kotlin.gradle.tasks.*

plugins {
    id("buildx-multiplatform-provider")
    id("buildx-target-native-all")
    id("buildx-use-openssl")

    id("org.jetbrains.dokka")
}

description = "cryptography-kotlin OpenSSL3 provider (API)"

tasks.withType<CInteropProcess>().configureEach {
    dependsOn(openssl.prepareOpensslTaskProvider)
    settings.includeDirs(openssl.includeDir(konanTarget))
}

kotlin {
    targets.all {
        if (this !is KotlinNativeTarget) return@all

        cinterop("declarations", "common")
    }
}
