import org.jetbrains.kotlin.gradle.targets.js.yarn.*

plugins {
    alias(libs.plugins.kotlin.multiplatform) apply false
    alias(libs.plugins.kotlin.serialization) apply false
    alias(libs.plugins.kotlin.dokka)
    alias(libs.plugins.kotlinx.bcv) apply false
    alias(libs.plugins.kotlinx.kover)
    alias(libs.plugins.gradle.versions)
}

plugins.withType<YarnPlugin> {
    yarn.lockFileDirectory = rootDir.resolve("gradle/js")
    yarn.yarnLockMismatchReport = YarnLockMismatchReport.WARNING
}

koverMerged {
    enable()
    filters {
        projects {
            val includes = setOf(
                "cryptography-core",
                "cryptography-random",
                "cryptography-jdk",
                "cryptography-behavior-tests",
                "cryptography-compatibility-tests",
            )
            excludes += allprojects
                .filter { it.buildFile.exists() && it.name !in includes }
                .map { it.name }
        }
    }
}
