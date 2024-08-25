/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import dev.whyoleg.sweetspi.gradle.*

plugins {
    kotlin("multiplatform")
    id("com.google.devtools.ksp")
    id("dev.whyoleg.sweetspi")
}

kotlin {
    withSweetSpi()
}
