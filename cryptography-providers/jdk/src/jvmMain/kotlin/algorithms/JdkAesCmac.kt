/*
 * Copyright (c) 2025-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.algorithms.*
import dev.whyoleg.cryptography.providers.jdk.*
import dev.whyoleg.cryptography.providers.jdk.operations.*
import javax.crypto.spec.*

internal class JdkAesCmac(
    private val state: JdkCryptographyState,
) : AES.CMAC, BaseAes<AES.CMAC.Key>() {
    // not supported by the default JDK provider
    private val mac = state.mac("AESCMAC")

    override fun wrapKey(rawKey: ByteArray): AES.CMAC.Key = AesCmacKey(rawKey)

    private inner class AesCmacKey(rawKey: ByteArray) : AES.CMAC.Key, BaseKey(rawKey) {
        private val secretKey: JSecretKey = SecretKeySpec(rawKey, "AESCMAC")

        private val signature = JdkMacSignature(mac, secretKey)

        override fun signatureGenerator(): SignatureGenerator = signature
        override fun signatureVerifier(): SignatureVerifier = signature
    }
}
