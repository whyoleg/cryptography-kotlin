import org.jetbrains.kotlin.gradle.plugin.mpp.*
import org.jetbrains.kotlin.konan.target.*

plugins {
    id("buildx-multiplatform-library")
    id("buildx-target-native-desktop")
    id("buildx-use-openssl")
}

description = "cryptography-kotlin OpenSSL3 provider (shared)"

kotlin {
    targets.all {
        if (this !is KotlinNativeTarget) return@all

        cinterop("linking", "common")

        if (this !is KotlinNativeTargetWithTests<*>) return@all

        // on CI, Linux by default has openssl built with newer glibc
        // which cause errors trying to link it with current K/N toolchain
        if (konanTarget.family == Family.LINUX) testRuns.all {
            executionSource.binary.linkTaskProvider.configure {
                dependsOn(openssl.prepareOpensslTaskProvider)
                binary.linkerOpts("-L${openssl.libDir(konanTarget).get().absolutePath}")
            }
        }
    }

    sourceSets {
        commonMain {
            dependencies {
                api(projects.cryptographyProviders.cryptographyOpenssl3.cryptographyOpenssl3Api)
            }
        }
        commonTest {
            dependencies {
                api(projects.cryptographyProviders.cryptographyOpenssl3.cryptographyOpenssl3Test)
            }
        }
    }
}
