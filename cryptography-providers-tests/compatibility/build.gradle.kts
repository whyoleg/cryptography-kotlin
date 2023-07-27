/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import buildparameters.tests.compatibility.*
import org.jetbrains.kotlin.gradle.plugin.*

plugins {
    id("build-parameters")
    id("buildx-multiplatform")
    id("buildx-target-all")
    id("buildx-target-android")

    id("org.jetbrains.kotlin.plugin.serialization")
    id("testtool.server")
}

val stepsToTest = mapOf(
    Step.InMemory to "inMemoryTest",
    Step.Generate to "generateStep",
    Step.Validate to "validateStep",
)
val step = buildParameters.tests.compatibility.step

kotlin {
    sourceSets {
        commonTest {
            dependencies {
                implementation(projects.cryptographyProvidersTestsSupport)
            }
        }
    }

    val excludedTests = stepsToTest
        .filterKeys { it != step }
        .map { "*.${it.value}" }
        .toTypedArray()
    targets.withType<KotlinTargetWithTests<*, *>>().configureEach {
        testRuns.configureEach {
            filter {
                setExcludePatterns(*excludedTests)
            }
        }
    }
}

android {
    defaultConfig {
        testInstrumentationRunnerArguments["tests_regex"] = ".*${stepsToTest.getValue(step)}"
    }
}
