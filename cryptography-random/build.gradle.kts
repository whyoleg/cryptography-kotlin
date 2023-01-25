plugins {
    id("buildx-multiplatform-library")
    id("org.jetbrains.kotlinx.binary-compatibility-validator")
    id("org.jetbrains.kotlinx.kover")
}

kotlin {
    allTargets()
}
