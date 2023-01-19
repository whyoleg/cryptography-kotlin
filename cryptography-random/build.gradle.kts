plugins {
    id("buildx-multiplatform-library")
}

kotlin {
    allTargets()
    sourceSets {
        commonTest {
            dependencies {
                implementation(projects.cryptographyTestSupport)
            }
        }
    }
}
