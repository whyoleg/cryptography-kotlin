plugins {
    id("buildx-multiplatform-provider")
    id("org.jetbrains.kotlinx.binary-compatibility-validator")
    id("org.jetbrains.kotlinx.kover")
    id("org.jetbrains.dokka")
}

kotlin {
    jvm()
}
