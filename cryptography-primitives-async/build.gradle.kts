plugins {
    `multiplatform-all`
}

kotlin {
    sourceSets {
        commonMain {
            dependencies {
                api(projects.external.vio)
                api(projects.external.biginteger)
            }
        }
    }
}
