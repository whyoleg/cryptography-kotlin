plugins {
    `kotlin-dsl`
}

dependencies {
    implementation(kotlinLibs.gradle.plugin)
    implementation(libs.kotlinx.bcv)
    implementation(libs.kotlinx.kover)
    implementation(libs.kotlin.dokka)
    implementation(libs.gradle.download)
}
