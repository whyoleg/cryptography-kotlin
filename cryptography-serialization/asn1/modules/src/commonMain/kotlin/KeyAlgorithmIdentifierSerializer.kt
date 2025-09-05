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
        is EcKeyAlgorithmIdentifier -> encodeParameters(EcParameters.serializer(), value.parameters)
        is UnknownKeyAlgorithmIdentifier -> encodeParameters(NothingSerializer(), value.parameters)
        else                             -> encodeParameters(NothingSerializer(), null)
    }

    override fun CompositeDecoder.decodeParameters(algorithm: ObjectIdentifier): KeyAlgorithmIdentifier = when (algorithm) {
        ObjectIdentifier.RSA -> {
            // null parameters
            decodeParameters<Nothing>(NothingSerializer())
            RsaKeyAlgorithmIdentifier
        }
        ObjectIdentifier.EC  -> EcKeyAlgorithmIdentifier(decodeParameters(EcParameters.serializer()))
        else                 -> {
            // For algorithms like Ed25519/Ed448/X25519/X448 (RFC 8410), parameters MUST be absent.
            // Some encoders still emit NULL; consume it if present to keep the decoder position in sync.
            decodeParameters<Nothing>(NothingSerializer())
            UnknownKeyAlgorithmIdentifier(algorithm)
        }
    }
}
