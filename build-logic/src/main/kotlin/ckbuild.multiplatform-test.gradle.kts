/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*

plugins {
    id("ckbuild.multiplatform")
}

kotlin {
    sourceSets.configureEach {
        languageSettings {
            optInForTests()
        }
    }
}
