import org.jetbrains.kotlin.gradle.plugin.mpp.*
import org.jetbrains.kotlin.gradle.tasks.*

plugins {
    id("buildx-multiplatform-library")
    id("buildx-use-openssl")
}

description = "cryptography-kotlin OpenSSL3 provider (static linking)"

tasks.withType<CInteropProcess>().configureEach {
    dependsOn(openssl.prepareOpensslTaskProvider)
    settings.extraOpts("-libraryPath", openssl.libDir(konanTarget).get().absolutePath)
}

kotlin {
    appleTargets()
    desktopTargets()

    targets.all {
        if (this !is KotlinNativeTarget) return@all

        cinterop("linking", "common")
    }

    sourceSets {
        commonMain {
            dependencies {
                api(projects.cryptographyProviders.cryptographyOpenssl3.cryptographyOpenssl3Api)
            }
        }
    }
}
