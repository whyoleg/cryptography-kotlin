/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.materials

import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.providers.jdk.*
import dev.whyoleg.cryptography.serialization.pem.*
import java.security.spec.*

internal abstract class JdkPublicKeyDecoder<KF : KeyFormat, K : Key>(
    protected val state: JdkCryptographyState,
    algorithm: String,
    private val pemAlgorithm: String = algorithm,
) : KeyDecoder<KF, K> {
    protected val keyFactory = state.keyFactory(algorithm)

    private fun decode(input: ByteArray): JPublicKey = keyFactory.use { it.generatePublic(X509EncodedKeySpec(input)) }

    protected abstract fun JPublicKey.convert(): K

    override fun decodeFromBlocking(format: KF, input: ByteArray): K = when (format.name) {
        "DER" -> decode(input)
        "PEM" -> decode(PEM.decode(input).ensurePemLabel(PemLabel.PublicKey).bytes)
        else  -> error("$format is not  supported")
    }.convert()
}
