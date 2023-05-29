/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

plugins {
    id("buildx-multiplatform")
}

kotlin {
    jvm {
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
}
