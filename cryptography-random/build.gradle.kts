plugins {
    id("buildx-multiplatform-library")
    id("buildx-target-all")
}

description = "cryptography-kotlin random API"

kotlin {
    linuxX64 {
        cinterop("random", "linux")
    }
}
