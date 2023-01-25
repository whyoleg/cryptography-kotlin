plugins {
    id("buildx-multiplatform")
    id("org.jetbrains.kotlinx.kover")
}

kotlin {
    allTargets()
    sourceSets {
        commonTest {
            dependencies {
                implementation(projects.cryptographyTests.cryptographyTestUtils)
            }
        }
    }
}
