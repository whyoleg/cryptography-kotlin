/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*

plugins {
    id("ckbuild.multiplatform-library")
}

description = "cryptography-kotlin Binary API"

kotlin {
    jvmTarget()
    jsTarget()
    nativeTargets()
    wasmTargets()
}
