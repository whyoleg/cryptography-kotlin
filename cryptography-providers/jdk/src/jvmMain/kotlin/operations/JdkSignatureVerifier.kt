/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.operations


import dev.whyoleg.cryptography.functions.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.jdk.*
import dev.whyoleg.cryptography.providers.jdk.internal.*
import java.security.spec.*

internal class JdkSignatureVerifier(
    state: JdkCryptographyState,
    private val key: JPublicKey,
    algorithm: String,
    private val parameters: AlgorithmParameterSpec?,
) : SignatureVerifier {
    private val signature = state.signature(algorithm)
    override fun createVerifyFunction(): VerifyFunction = JdkVerifyFunction(key, parameters, signature.borrowResource())
}

private class JdkVerifyFunction(
    private val key: JPublicKey,
    private val parameters: AlgorithmParameterSpec?,
    private val jsignature: Pooled.Resource<JSignature>,
) : VerifyFunction {
    init {
        reset()
    }

    override fun update(source: ByteArray, startIndex: Int, endIndex: Int) {
        checkBounds(source.size, startIndex, endIndex)
        val jsignature = jsignature.access()
        jsignature.update(source, startIndex, endIndex - startIndex)
    }

    override fun verify(signature: ByteArray, startIndex: Int, endIndex: Int): Boolean {
        checkBounds(signature.size, startIndex, endIndex)
        val jsignature = jsignature.access()

        return jsignature.verify(signature, startIndex, endIndex - startIndex)
    }

    override fun reset() {
        val jsignature = jsignature.access()
        jsignature.initVerify(key)
        parameters?.let(jsignature::setParameter)
    }

    override fun close() {
        jsignature.close()
    }
}
