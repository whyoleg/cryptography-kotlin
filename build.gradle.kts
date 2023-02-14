import kotlinx.validation.*
import org.jetbrains.kotlin.gradle.targets.js.yarn.*

plugins {
    id("build-parameters")

    alias(kotlinLibs.plugins.multiplatform) apply false
    alias(kotlinLibs.plugins.serialization) apply false
    alias(libs.plugins.kotlin.dokka)
    alias(libs.plugins.kotlinx.bcv) apply false
    alias(libs.plugins.kotlinx.kover)
    alias(libs.plugins.gradle.versions)
}

plugins.withType<YarnPlugin> {
    yarn.apply {
        lockFileDirectory = rootDir.resolve("gradle/js")
        yarnLockMismatchReport = YarnLockMismatchReport.WARNING
        resolution("ua-parser-js", "0.7.33")
    }
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

val skipTest = buildParameters.skip.test
val skipLink = buildParameters.skip.link
val kotlinVersionOverriden = buildParameters.kotlin.override.version.isPresent

subprojects {
    tasks.whenTaskAdded {
        if (name.endsWith("test", ignoreCase = true)) onlyIf { !skipTest }
        if (name.startsWith("link", ignoreCase = true)) onlyIf { !skipLink }
    }
    plugins.withType<BinaryCompatibilityValidatorPlugin> {
        extensions.configure<ApiValidationExtension>("apiValidation") {
            validationDisabled = kotlinVersionOverriden
        }
    }
}
