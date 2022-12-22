plugins {
    id("buildx-multiplatform")
}

kotlin {
    jvm()
    js {
        nodejs()
    }
    linuxX64()
    macosX64()
    macosArm64()
    mingwX64()
}
