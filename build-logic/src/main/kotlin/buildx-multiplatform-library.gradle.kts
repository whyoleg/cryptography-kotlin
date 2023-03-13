import org.jetbrains.kotlin.gradle.plugin.*

plugins {
    id("buildx-multiplatform")
    id("buildx-publish")

    id("org.jetbrains.dokka")
    id("org.jetbrains.kotlinx.binary-compatibility-validator")
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

apiValidation {
    // in kotlin 1.9 Enum.entries were added because of which binary compatibility validator check fails
    validationDisabled = getKotlinPluginVersion().also(::println).startsWith("1.9")
}
