/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import buildparameters.tests.compatibility.*
import org.jetbrains.kotlin.gradle.plugin.*

plugins {
    id("build-parameters")
    id("buildx-multiplatform")
    id("buildx-target-all")

    id("org.jetbrains.kotlin.plugin.serialization")
    id("testtool.server")
}

kotlin {
    sourceSets {
        commonTest {
            dependencies {
                implementation(projects.cryptographyProvidersTestsSupport)
                implementation(libs.kotlinx.serialization.json)

                // drop after kotlin 1.8.20 (needed only for base64)
                implementation(libs.ktor.utils)
            }
        }
    }

    val excludedTests = mapOf(
        Step.InMemory to "*.inMemoryTest",
        Step.Generate to "*.generateStep",
        Step.Validate to "*.validateStep",
    ).filterKeys { it != buildParameters.tests.compatibility.step }.values.toTypedArray()
    targets.configureEach {
        if (this is KotlinTargetWithTests<*, *>) testRuns.configureEach {
            filter {
                setExcludePatterns(*excludedTests)
            }
        }
    }
}
