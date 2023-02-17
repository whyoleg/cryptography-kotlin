plugins {
    id("buildx-multiplatform")
    id("buildx-publish")
}

kotlin {
    explicitApi()

    //version enforcement using bom works only for jvm
    sourceSets.all {
        if (name == "jvmMain") dependencies {
            api(platform(project(":cryptography-bom")))
        }
    }
}
