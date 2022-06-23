plugins {
    `multiplatform-base`
}

kotlin {
    macosX64()
    macosArm64()

    sourceSets {
        val commonMain by getting {
            dependencies {
                api(projects.cryptographyCore)
            }
        }
    }
}
