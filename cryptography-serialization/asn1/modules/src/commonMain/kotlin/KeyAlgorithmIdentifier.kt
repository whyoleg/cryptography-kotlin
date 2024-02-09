/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1.modules

import dev.whyoleg.cryptography.serialization.asn1.*
import kotlinx.serialization.*
import kotlinx.serialization.builtins.*
import kotlinx.serialization.encoding.*

@Serializable(KeyAlgorithmIdentifierSerializer::class)
public interface KeyAlgorithmIdentifier : AlgorithmIdentifier

// this should be used to be able to override serializers
public typealias ContextualKeyAlgorithmIdentifier = @Contextual KeyAlgorithmIdentifier

public object KeyAlgorithmIdentifierSerializer : AlgorithmIdentifierSerializer<KeyAlgorithmIdentifier>() {
    @OptIn(ExperimentalSerializationApi::class)
    override fun CompositeEncoder.encodeParameters(value: KeyAlgorithmIdentifier): Unit = when (value) {
        is RsaPssKeyAlgorithmIdentifier  -> encodeParameters(RsaPssKeyAlgorithmParameters.serializer(), value.parameters)
        is RsaOaepKeyAlgorithmIdentifier -> encodeParameters(RsaOaepKeyAlgorithmParameters.serializer(), value.parameters)
        is RsaKeyAlgorithmIdentifier     -> encodeParameters(NothingSerializer(), value.parameters)
        is UnknownKeyAlgorithmIdentifier -> encodeParameters(NothingSerializer(), value.parameters)
        else                             -> encodeParameters(NothingSerializer(), null)
    }

    override fun CompositeDecoder.decodeParameters(algorithm: ObjectIdentifier): KeyAlgorithmIdentifier = when (algorithm) {
        ObjectIdentifier.RSA      -> RsaKeyAlgorithmIdentifier
        ObjectIdentifier.RSA_PSS  -> RsaPssKeyAlgorithmIdentifier(decodeParameters(RsaPssKeyAlgorithmParameters.serializer()))
        ObjectIdentifier.RSA_OAEP -> RsaOaepKeyAlgorithmIdentifier(decodeParameters(RsaOaepKeyAlgorithmParameters.serializer()))
        else                      -> UnknownKeyAlgorithmIdentifier(algorithm)
    }
}

public class UnknownKeyAlgorithmIdentifier(override val algorithm: ObjectIdentifier) : KeyAlgorithmIdentifier {
    override val parameters: Nothing? get() = null
}

public object RsaKeyAlgorithmIdentifier : KeyAlgorithmIdentifier {
    override val algorithm: ObjectIdentifier get() = ObjectIdentifier.RSA
    override val parameters: Nothing? get() = null
}

public class RsaPssKeyAlgorithmIdentifier(override val parameters: RsaPssKeyAlgorithmParameters? = null) : KeyAlgorithmIdentifier {
    override val algorithm: ObjectIdentifier get() = ObjectIdentifier.RSA_PSS
}

public class RsaOaepKeyAlgorithmIdentifier(override val parameters: RsaOaepKeyAlgorithmParameters? = null) : KeyAlgorithmIdentifier {
    override val algorithm: ObjectIdentifier get() = ObjectIdentifier.RSA_PSS
}
