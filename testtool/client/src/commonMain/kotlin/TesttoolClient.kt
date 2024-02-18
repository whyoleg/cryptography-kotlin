/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.testtool.client

import kotlinx.coroutines.flow.*

object TesttoolClient {

    object Compatibility {

        suspend fun saveParameters(algorithm: String, path: String, bytes: ByteArray): String =
            postData("compatibility/$algorithm/$path", bytes)

        fun getParameters(algorithm: String, path: String): Flow<Pair<String, ByteArray>> =
            getData("compatibility/$algorithm/$path")

        suspend fun saveData(algorithm: String, path: String, parametersId: String, bytes: ByteArray): String =
            postData("compatibility/$algorithm/$path/$parametersId/data", bytes)

        fun getData(algorithm: String, path: String, parametersId: String): Flow<Pair<String, ByteArray>> =
            getData("compatibility/$algorithm/$path/$parametersId/data")
    }
}

internal expect fun hostOverride(): String?

internal expect suspend fun postData(path: String, bytes: ByteArray): String

internal expect fun getData(path: String): Flow<Pair<String, ByteArray>>
