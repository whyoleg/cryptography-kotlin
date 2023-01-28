plugins {
    id("buildx-multiplatform")
    `maven-publish`
}

kotlin {
    explicitApi()

    //version enforcement using bom works only for jvm
    sourceSets.findByName("jvmMain")?.dependencies {
        api(platform(project(":cryptography-bom")))
    }
}
