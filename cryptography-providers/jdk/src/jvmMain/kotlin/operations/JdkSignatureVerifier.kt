/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.operations


import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.jdk.*
import java.security.spec.*

internal class JdkSignatureVerifier(
    state: JdkCryptographyState,
    private val key: JPublicKey,
    algorithm: String,
    private val parameters: AlgorithmParameterSpec?,
) : SignatureVerifier {
    private val signature = state.signature(algorithm)

    override fun verifySignatureBlocking(data: ByteArray, signature: ByteArray): Boolean = this.signature.use { jSignature ->
        jSignature.initVerify(key)
        parameters?.let(jSignature::setParameter)
        jSignature.update(data)
        jSignature.verify(signature)
    }
}
