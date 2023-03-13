plugins {
    id("buildx-multiplatform-library")
    id("org.jetbrains.kotlinx.binary-compatibility-validator")
    id("org.jetbrains.kotlinx.kover")
    id("org.jetbrains.dokka")
}

description = "cryptography-kotlin random API"

kotlin {
    allTargets()

    linuxX64 {
        val main by compilations.getting {
            val random by cinterops.creating {
                defFile("linux.def")
            }
        }
    }
}
