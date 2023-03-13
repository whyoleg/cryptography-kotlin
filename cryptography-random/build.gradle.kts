plugins {
    id("buildx-multiplatform-library")
    id("buildx-target-all")

    id("org.jetbrains.kotlinx.binary-compatibility-validator")
    id("org.jetbrains.kotlinx.kover")
    id("org.jetbrains.dokka")
}

description = "cryptography-kotlin random API"

kotlin {
    linuxX64 {
        cinterop("random", "linux")
    }
}
