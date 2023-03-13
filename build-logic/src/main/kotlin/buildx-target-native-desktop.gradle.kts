plugins {
    id("buildx-multiplatform-native")
}

kotlin {
    macosX64()
    macosArm64()

    linuxX64()
    mingwX64()
}
