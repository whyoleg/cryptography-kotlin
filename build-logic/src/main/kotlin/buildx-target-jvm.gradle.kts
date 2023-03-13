plugins {
    id("buildx-multiplatform")
}

kotlin {
    jvm {
        //setup additional testing on different JDK versions (default task jvmTest will run on JDK8)
        listOf(11, 17, 19).forEach { jdkVersion ->
            testRuns.create("${jdkVersion}Test") {
                executionTask.configure {
                    javaLauncher.set(
                        //project.javaToolchains //need Gradle 8
                        project.extensions.getByType<JavaToolchainService>().launcherFor {
                            languageVersion.set(JavaLanguageVersion.of(jdkVersion))
                        }
                    )
                }
            }
        }
    }
}
