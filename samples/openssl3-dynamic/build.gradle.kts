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
            entryPoint("dev.whyoleg.cryptography.samples.openssl3.dynamic.main")
        }
    }

    sourceSets {
        commonMain {
            dependencies {
                implementation(libs.cryptography.openssl3.dynamic)
            }
        }
    }
}
