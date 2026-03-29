/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.gradle

object TestsArguments {
    val devArtifactsDirectories = systemProperty("dev-artifacts-directories").split(",")
    val devArtifactsVersion = systemProperty("dev-artifacts-version")

    private fun systemProperty(name: String): String = checkNotNull(System.getProperty("cktests.$name")) {
        "'cktests.$name' is missing in the system properties"
    }
}
