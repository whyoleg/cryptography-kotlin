plugins {
    `kotlin-dsl`
}

dependencies {
    implementation(kotlinLibs.gradle.plugin)
    implementation("de.undercouch:gradle-download-task:5.3.0")
}
