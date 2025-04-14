/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.openssl3.operations.*
import kotlinx.cinterop.*
import kotlin.experimental.*

@OptIn(ExperimentalNativeApi::class)
internal object Openssl3AesCmac : AES.CMAC, Openssl3Aes<AES.CMAC.Key>() {
    override fun wrapKey(keySize: BinarySize, key: ByteArray): AES.CMAC.Key = AesCmacKey(keySize, key)

    private class AesCmacKey(keySize: BinarySize, key: ByteArray) : AES.CMAC.Key, AesKey(key) {
        private val algorithm = when (keySize) {
            AES.Key.Size.B128 -> "AES-128-CBC"
            AES.Key.Size.B192 -> "AES-192-CBC"
            AES.Key.Size.B256 -> "AES-256-CBC"
            else              -> error("Unsupported key size")
        }

        private fun createFunction() = AesCmacSignature(
            algorithm = algorithm,
            key = key
        )

        override fun signatureGenerator(): SignatureGenerator = createFunction()
        override fun signatureVerifier(): SignatureVerifier = createFunction()
    }
}

@OptIn(UnsafeNumber::class)
@ExperimentalNativeApi
private class AesCmacSignature(
    private val algorithm: String,
    private val key: ByteArray,
) : SignatureGenerator, SignatureVerifier {

    override fun createSignFunction(): SignFunction {
        return Openssl3CmacSignatureGenerator(
            key = key,
            algorithm = algorithm
        ).createSignFunction()
    }

    override fun createVerifyFunction(): VerifyFunction {
        return Openssl3CmacSignatureVerifier(
            key = key,
            algorithm = algorithm
        ).createVerifyFunction()
    }
}