plugins {
    id("buildx-multiplatform")
    id("buildx-target-all")
    id("org.jetbrains.kotlinx.kover")
}

kotlin {
    sourceSets {
        commonTest {
            dependencies {
                implementation(projects.cryptographyTests.cryptographyTestUtils)
            }
        }
    }
}
