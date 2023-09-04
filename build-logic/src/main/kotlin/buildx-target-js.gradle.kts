/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

plugins {
    id("buildx-multiplatform")
}

kotlin {
    js {
        nodejs {
            testTask(Action {
                useMocha {
                    timeout = "1800s"
                }
            })
        }
        browser {
            testTask(Action {
                useKarma {
                    useConfigDirectory(project.rootDir.resolve("gradle/js/karma"))
                    useChromeHeadless()
                }
            })
        }
    }
}
