plugins {
    id("buildx-multiplatform")
}

kotlin {
    js {
        nodejs {
            testTask {
                useMocha {
                    timeout = "600s"
                }
            }
        }
        browser {
            testTask {
                useKarma {
                    useConfigDirectory(project.rootDir.resolve("gradle/js/karma"))
                    useChromeHeadless()
                }
            }
        }
    }
}
