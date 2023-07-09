/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.tests.compatibility.api

sealed class CompatibilityApi {
    abstract val keys: CompatibilityStorageApi
    abstract val keyPairs: CompatibilityStorageApi
    abstract val digests: CompatibilityStorageApi
    abstract val signatures: CompatibilityStorageApi
    abstract val ciphers: CompatibilityStorageApi
}
