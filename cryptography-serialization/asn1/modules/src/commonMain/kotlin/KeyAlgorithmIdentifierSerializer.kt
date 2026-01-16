/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
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
        is EcKeyAlgorithmIdentifier      -> encodeParameters(EcParameters.serializer(), value.parameters)
        // For EdDSA, XDH, and other algorithms using UnknownKeyAlgorithmIdentifier,
        // parameters MUST be absent (RFC 8410), not NULL
        is UnknownKeyAlgorithmIdentifier -> {} // Don't encode - parameters absent
        else                             -> {} // Don't encode - parameters absent
    }

    override fun CompositeDecoder.decodeParameters(algorithm: ObjectIdentifier): KeyAlgorithmIdentifier = when (algorithm) {
        ObjectIdentifier.RSA -> {
            // null parameters
            decodeParameters<Nothing>(NothingSerializer())
            RsaKeyAlgorithmIdentifier
        }
        ObjectIdentifier.EC  -> EcKeyAlgorithmIdentifier(decodeParameters(EcParameters.serializer()))
        else                 -> {
            // TODO: somehow we should ignore parameters here
            UnknownKeyAlgorithmIdentifier(algorithm)
        }
    }

    override fun CompositeDecoder.decodeAbsentParameters(algorithm: ObjectIdentifier): KeyAlgorithmIdentifier {
        return UnknownKeyAlgorithmIdentifier(algorithm)
    }
}
