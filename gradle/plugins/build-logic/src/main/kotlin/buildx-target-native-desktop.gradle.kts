/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

plugins {
    id("buildx-multiplatform-native")
}

kotlin {
    macosX64()
    macosArm64()

    linuxX64()
    mingwX64()
}
