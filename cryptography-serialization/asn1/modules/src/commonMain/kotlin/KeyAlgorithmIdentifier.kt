/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1.modules

import dev.whyoleg.cryptography.serialization.asn1.*
import dev.whyoleg.cryptography.serialization.asn1.modules.rsa.*
import kotlinx.serialization.*
import kotlinx.serialization.builtins.*
import kotlinx.serialization.encoding.*

// TODO!!!
@Serializable(KeyAlgorithmIdentifierSerializer::class)
public interface KeyAlgorithmIdentifier : AlgorithmIdentifier

public class UnknownKeyAlgorithmIdentifier(override val algorithm: ObjectIdentifier) : KeyAlgorithmIdentifier {
    override val parameters: Nothing? get() = null
}

internal object KeyAlgorithmIdentifierSerializer : AlgorithmIdentifierSerializer<KeyAlgorithmIdentifier>() {
    @OptIn(ExperimentalSerializationApi::class)
    override fun CompositeEncoder.encodeParameters(value: KeyAlgorithmIdentifier): Unit = when (value) {
//        is RsaPssAlgorithmIdentifier     -> encodeParameters(RsaPssAlgorithmParameters.serializer(), value.parameters)
//        is RsaOaepAlgorithmIdentifier    -> encodeParameters(RsaOaepAlgorithmParameters.serializer(), value.parameters)
        is RsaKeyAlgorithmIdentifier     -> encodeParameters(NothingSerializer(), value.parameters)
        is UnknownKeyAlgorithmIdentifier -> encodeParameters(NothingSerializer(), value.parameters)
        else                             -> encodeParameters(NothingSerializer(), null)
    }

    override fun CompositeDecoder.decodeParameters(algorithm: ObjectIdentifier): KeyAlgorithmIdentifier = when (algorithm) {
        ObjectIdentifier.RSA -> RsaKeyAlgorithmIdentifier
//        ObjectIdentifier.RSA_PSS  -> RsaPssAlgorithmIdentifier(decodeParameters(RsaPssAlgorithmParameters.serializer()))
//        ObjectIdentifier.RSA_OAEP -> RsaOaepAlgorithmIdentifier(decodeParameters(RsaOaepAlgorithmParameters.serializer()))
        else                 -> UnknownKeyAlgorithmIdentifier(algorithm)
    }
}
