/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

@file:Suppress("UnstableApiUsage")

package ckbuild.tests

import com.android.build.api.dsl.*
import org.gradle.api.*
import org.gradle.api.tasks.testing.*
import org.gradle.kotlin.dsl.*
import org.jetbrains.kotlin.gradle.dsl.*
import org.jetbrains.kotlin.gradle.plugin.*

class TestFilters(
    val androidTestRegex: String,
    val kotlinTestFilter: TestFilter.() -> Unit,
)

fun Project.applyProviderTestFilters() {
    val providerTestsStep = providers.gradleProperty("ckbuild.providerTests.step").orNull

    val testFilters = when (providerTestsStep) {
        null                           -> TestFilters(
            androidTestRegex = "^((?!CompatibilityTest#(generateStep|generateStressStep|validateStep)).)*$",
            kotlinTestFilter = {
                setExcludePatterns(
                    "*CompatibilityTest.generateStep",
                    "*CompatibilityTest.generateStressStep",
                    "*CompatibilityTest.validateStep"
                )
            }
        )
        "compatibility.generate"       -> TestFilters(
            androidTestRegex = "^.*CompatibilityTest#generateStep$",
            kotlinTestFilter = {
                setIncludePatterns("*CompatibilityTest.generateStep")
            }
        )
        "compatibility.generateStress" -> TestFilters(
            androidTestRegex = "^.*CompatibilityTest#generateStressStep$",
            kotlinTestFilter = {
                setIncludePatterns("*CompatibilityTest.generateStressStep")
            }
        )
        "compatibility.validate"       -> TestFilters(
            androidTestRegex = "^.*CompatibilityTest#validateStep$",
            kotlinTestFilter = {
                setIncludePatterns("*CompatibilityTest.validateStep")
            }
        )
        else                           -> error("wrong argument")
    }

    plugins.withId("org.jetbrains.kotlin.multiplatform") {
        extensions.configure<KotlinMultiplatformExtension>("kotlin") {
            targets.withType<KotlinTargetWithTests<*, *>>().configureEach {
                testRuns.configureEach {
                    filter(testFilters.kotlinTestFilter)
                }
            }

            plugins.withId("com.android.kotlin.multiplatform.library") {
                androidLibrary {
                    compilations.withType(KotlinMultiplatformAndroidDeviceTestCompilation::class).configureEach {
                        instrumentationRunnerArguments["tests_regex"] = testFilters.androidTestRegex
                    }
                }
            }
        }
    }
}
