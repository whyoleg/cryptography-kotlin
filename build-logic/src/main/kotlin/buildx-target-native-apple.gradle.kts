plugins {
    id("buildx-multiplatform-native")
}

kotlin {
    macosX64()
    macosArm64()

    iosArm64()
    iosX64()
    iosSimulatorArm64()
}
