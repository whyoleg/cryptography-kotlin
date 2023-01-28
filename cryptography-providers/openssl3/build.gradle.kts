import de.undercouch.gradle.tasks.download.*
import org.jetbrains.kotlin.gradle.plugin.mpp.*
import org.jetbrains.kotlin.gradle.tasks.*
import org.jetbrains.kotlin.konan.target.*

plugins {
    id("buildx-multiplatform-provider")
    id("org.jetbrains.dokka")
    id("de.undercouch.download")
}

val downloadPrebuiltOpenSSL3 by tasks.registering(Download::class) {
    src(libs.versions.openssl3.map { "https://github.com/whyoleg/openssl-builds/releases/download/$it/openssl3-all.zip" })
    onlyIfModified(true)
    overwrite(false)
    dest(buildDir.resolve("openssl3-all.zip"))
}

val unzipPrebuiltOpenSSL3 by tasks.registering(Sync::class) {
    from(downloadPrebuiltOpenSSL3.map { zipTree(it.dest) })
    into(buildDir.resolve("openssl3-prebuilt"))
}

tasks.withType<CInteropProcess>().configureEach {
    dependsOn(unzipPrebuiltOpenSSL3)
}

kotlin {
    appleTargets()
    desktopTargets()

    targets.all {
        if (this !is KotlinNativeTarget) return@all
        val main by compilations.getting {
            val libcrypto by cinterops.creating {
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
                defFile("libcrypto.def")
                includeDirs(unzipPrebuiltOpenSSL3.map { it.destinationDir.resolve("$prebuiltName/include") })
            }
        }
    }
}
