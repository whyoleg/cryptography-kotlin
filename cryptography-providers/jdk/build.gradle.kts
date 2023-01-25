plugins {
    id("buildx-multiplatform-provider")
    id("org.jetbrains.kotlinx.binary-compatibility-validator")
    id("org.jetbrains.kotlinx.kover")
}

kotlin {
    jvm()
}
