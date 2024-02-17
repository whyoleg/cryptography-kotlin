/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1.modules

import dev.whyoleg.cryptography.serialization.asn1.*
import kotlinx.serialization.*
import kotlinx.serialization.builtins.*
import kotlinx.serialization.encoding.*

@OptIn(ExperimentalSerializationApi::class)
internal object KeyAlgorithmIdentifierSerializer : AlgorithmIdentifierSerializer<KeyAlgorithmIdentifier>() {
    override fun CompositeEncoder.encodeParameters(value: KeyAlgorithmIdentifier): Unit = when (value) {
        is RsaKeyAlgorithmIdentifier     -> encodeParameters(NothingSerializer(), RsaKeyAlgorithmIdentifier.parameters)
        is UnknownKeyAlgorithmIdentifier -> encodeParameters(NothingSerializer(), value.parameters)
        else                             -> encodeParameters(NothingSerializer(), null)
    }

    override fun CompositeDecoder.decodeParameters(algorithm: ObjectIdentifier): KeyAlgorithmIdentifier = when (algorithm) {
        ObjectIdentifier.RSA -> RsaKeyAlgorithmIdentifier
        else                 -> UnknownKeyAlgorithmIdentifier(algorithm)
    }
}
