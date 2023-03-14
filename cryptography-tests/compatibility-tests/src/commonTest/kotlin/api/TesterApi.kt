/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.tests.compatibility.api

sealed class TesterApi {
    abstract val keys: TesterStorageApi
    abstract val keyPairs: TesterStorageApi
    abstract val digests: TesterStorageApi
    abstract val signatures: TesterStorageApi
    abstract val ciphers: TesterStorageApi
}
