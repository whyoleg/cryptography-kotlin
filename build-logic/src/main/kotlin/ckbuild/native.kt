/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package ckbuild

import org.jetbrains.kotlin.gradle.plugin.mpp.*

fun KotlinNativeTarget.cinterop(
    defFileName: String,
    groupName: String = "common",
    compilationName: String = "main",
    block: DefaultCInteropSettings.() -> Unit = {},
) {
    compilations.getByName(compilationName) {
        cinterops.create(defFileName) {
            defFile("src/${groupName}${compilationName.replaceFirstChar(Char::uppercase)}/cinterop/$defFileName.def")
            block()
        }
    }
}
