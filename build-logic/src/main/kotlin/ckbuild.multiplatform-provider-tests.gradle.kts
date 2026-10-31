/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

plugins {
    id("ckbuild.multiplatform")
    id("ckbuild.provider-tests")
}

kotlin {
    sourceSets.commonTest.dependencies {
        implementation(project(":cryptography-tests"))
    }
}
