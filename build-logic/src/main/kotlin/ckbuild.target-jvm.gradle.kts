/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import org.jetbrains.kotlin.gradle.*
import org.jetbrains.kotlin.gradle.targets.jvm.tasks.*

plugins {
    id("ckbuild.multiplatform")
}

@OptIn(ExperimentalKotlinGradlePluginApi::class)
kotlin {
    jvm {
        compilations.configureEach {
            compilerOptions.configure {
                freeCompilerArgs.add("-Xjvm-default=all")
            }
        }
        //setup additional testing on different JDK versions (default task jvmTest will run on JDK8)
        listOf(11, 17, 20).forEach { jdkVersion ->
            testRuns.create("${jdkVersion}Test") {
                executionTask.configure {
                    javaLauncher.set(
                        project.javaToolchains.launcherFor {
                            languageVersion.set(JavaLanguageVersion.of(jdkVersion))
                        }
                    )
                }
            }
        }
    }

    sourceSets {
        //version enforcement using bom works only for jvm
        getByName("jvmMain") {
            dependencies {
                api(project.dependencies.platform(project(":cryptography-bom")))
            }
        }
        getByName("jvmTest") {
            dependencies {
                implementation(kotlin("test-junit"))
            }
        }
    }
}

tasks.register("jvmAllTest") {
    group = "verification"
    dependsOn(tasks.withType<KotlinJvmTest>())
}
