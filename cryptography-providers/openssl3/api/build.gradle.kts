import org.jetbrains.kotlin.gradle.plugin.mpp.*
import org.jetbrains.kotlin.gradle.tasks.*

plugins {
    id("buildx-multiplatform-provider")
    id("org.jetbrains.dokka")
    id("buildx-use-openssl")
}

description = "cryptography-kotlin OpenSSL3 provider (API)"

tasks.withType<CInteropProcess>().configureEach {
    dependsOn(openssl.prepareOpensslTaskProvider)
    settings.includeDirs(openssl.includeDir(konanTarget))
}

kotlin {
    appleTargets()
    desktopTargets()

    targets.all {
        if (this !is KotlinNativeTarget) return@all

        cinterop("declarations", "common")
    }
}
