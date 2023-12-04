/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*
import org.jetbrains.kotlin.gradle.*
import org.jetbrains.kotlin.gradle.plugin.*

plugins {
    id("ckbuild.multiplatform-base")
    id("ckbuild.multiplatform-android")

    id("org.jetbrains.kotlin.plugin.serialization")
    id("testtool.server")
}

val stepsToTest = mapOf(
    "InMemory" to "inMemoryTest",
    "Generate" to "generateStep",
    "Validate" to "validateStep",
)
val step = providers.gradleProperty("tests.compatibility.step").getOrElse("InMemory")

@OptIn(ExperimentalKotlinGradlePluginApi::class)
kotlin {
    jvmTarget()
    jsTarget()
    nativeTargets()

    compilerOptions {
        optIn.addAll(
            OptIns.CryptographyProviderApi,
            OptIns.InsecureAlgorithm,

            OptIns.ExperimentalEncodingApi,
        )
    }

    applyDefaultHierarchyTemplate {
        common {
            group("nonJs") {
                withJvm()
                withWasm()
                withNative()
                withAndroidTarget()
            }
        }
    }

    sourceSets.commonTest.dependencies {
        implementation(projects.cryptographyProvidersTestsSupport)
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
