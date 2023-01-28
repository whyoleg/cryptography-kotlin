plugins {
    kotlin("multiplatform")
}

kotlin {
    listOf(
        linuxX64(),
        macosArm64(),
        macosX64(),
        mingwX64()
    ).forEach {
        it.binaries.executable {
            entryPoint("dev.whyoleg.cryptography.samples.openssl3.static.main")
        }
    }

    sourceSets {
        commonMain {
            dependencies {
                implementation(libsCryptography.openssl3.static)
            }
        }
    }
}
