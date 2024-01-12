/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.internal

@Suppress("ACTUAL_CLASSIFIER_MUST_HAVE_THE_SAME_SUPERTYPES_AS_NON_FINAL_EXPECT_CLASSIFIER_WARNING")
internal actual external interface CryptoKey : JsAny

@Suppress("ACTUAL_CLASSIFIER_MUST_HAVE_THE_SAME_SUPERTYPES_AS_NON_FINAL_EXPECT_CLASSIFIER_WARNING")
internal actual external interface CryptoKeyPair : JsAny {
    actual val privateKey: CryptoKey
    actual val publicKey: CryptoKey
}

internal actual val CryptoKey.algorithmName: String get() = keyAlgorithmName(this)
private fun keyAlgorithmName(key: CryptoKey): String = js("key.algorithm.hash.name")
