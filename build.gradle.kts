import org.jetbrains.kotlin.gradle.targets.js.yarn.*

plugins {
    alias(libs.plugins.kotlin.multiplatform) apply false
    alias(libs.plugins.kotlin.serialization) apply false
    alias(libs.plugins.kotlinx.bcv) apply false
    alias(libs.plugins.gradle.versions)
}

plugins.withType<YarnPlugin> {
    yarn.lockFileDirectory = rootDir.resolve("gradle/js")
    yarn.yarnLockMismatchReport = YarnLockMismatchReport.WARNING
}
