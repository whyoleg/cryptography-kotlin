/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

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
