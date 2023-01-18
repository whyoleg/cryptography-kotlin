import buildparameters.testsuite.*
import org.jetbrains.kotlin.gradle.plugin.*

plugins {
    id("buildx-multiplatform")
    id("build-parameters")
    kotlin("plugin.serialization")
}

kotlin {
    allTargets()
    sourceSets {
        commonTest {
            dependencies {
                implementation(projects.cryptographyTestSupport)
                implementation(projects.cryptographyTestVectorsClient)
                implementation(libs.ktor.utils) //for base64
                implementation(libs.kotlinx.serialization.json)
            }
        }
    }

    //TESTS SHOULD BE ALWAYS ONLY IN `tests` folder
    val testsPackage = "dev.whyoleg.cryptography.test.vectors.suite.tests.*."
    val tests = mapOf(
        Step.Local to "localTest",
        Step.Generate to "generateTestStep",
        Step.Compute to "validateTestStep",
        Step.Validate to "computeTestStep",
    )
    val includedTest = tests[buildParameters.testsuite.step]!!
    val excludedTests = tests.values.filter { it != includedTest }

    val testFilter: TestFilter.() -> Unit = {
        excludedTests.forEach {
            excludeTestsMatching("${testsPackage}$it")
        }
    }
    targets.all { if (this is KotlinTargetWithTests<*, *>) testRuns.all { filter(testFilter) } }
}
