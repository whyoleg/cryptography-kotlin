import org.jetbrains.kotlin.gradle.plugin.mpp.*
import org.jetbrains.kotlin.konan.target.*

plugins {
    id("buildx-multiplatform-provider")
    id("org.jetbrains.dokka")
}

kotlin {
    appleTargets()
    desktopTargets()

    targets.all {
        if (this !is KotlinNativeTarget) return@all

        val main by compilations.getting {
            val openssl3 by cinterops.creating {
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
                defFile("cinterop/openssl3.def")
                includeDirs("prebuilt/$prebuiltName/include")
            }
        }
    }
}
