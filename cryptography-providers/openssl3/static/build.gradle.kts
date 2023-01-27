import org.jetbrains.kotlin.gradle.plugin.mpp.*
import org.jetbrains.kotlin.konan.target.*

plugins {
    id("buildx-multiplatform-library")
}

kotlin {
    appleTargets()
    desktopTargets()

    sourceSets {
        commonMain {
            dependencies {
                api(projects.cryptographyProviders.cryptographyOpenssl3)
            }
        }
    }

    targets.all {
        if (this !is KotlinNativeTarget) return@all

        //TODO: will it work after publication?
        compilations.all {
            val prebuiltName = when (konanTarget) {
                KonanTarget.IOS_ARM64           -> "ios-device-arm64"
                KonanTarget.IOS_SIMULATOR_ARM64 -> "ios-simulator-arm64"
                KonanTarget.IOS_X64             -> "ios-simulator-x64"
                KonanTarget.LINUX_X64           -> "linux-x64"
                KonanTarget.MACOS_ARM64         -> "macos-arm64"
                KonanTarget.MACOS_X64           -> "macos-x64"
                KonanTarget.MINGW_X64           -> "mingw-x64"
                else                            -> TODO("Unsupported target: $konanTarget")
            }
            kotlinOptions.freeCompilerArgs += listOf(
                "-include-binary",
                file("../prebuilt/$prebuiltName/lib/libcrypto.a").absolutePath
            )
        }
    }
}
