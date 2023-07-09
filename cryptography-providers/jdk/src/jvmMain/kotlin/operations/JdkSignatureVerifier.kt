/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.operations


import dev.whyoleg.cryptography.providers.jdk.*
import dev.whyoleg.cryptography.operations.signature.*
import java.security.spec.*

internal class JdkSignatureVerifier(
    private val state: JdkCryptographyState,
    private val key: JPublicKey,
    algorithm: String,
    private val parameters: AlgorithmParameterSpec?,
) : SignatureVerifier {
    private val signature = state.signature(algorithm)

    override fun verifySignatureBlocking(dataInput: ByteArray, signatureInput: ByteArray): Boolean = signature.use { signature ->
        signature.initVerify(key)
        parameters?.let(signature::setParameter)
        signature.update(dataInput)
        signature.verify(signatureInput)
    }
}
