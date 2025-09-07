import ckbuild.*

plugins {
    id("ckbuild.multiplatform-library")
}

description = "cryptography-kotlin storage API (experimental)"

kotlin {
    allTargets()

    sourceSets.commonMain.dependencies {
        api(projects.cryptographyCore)
    }
}

