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
    override fun CompositeEncoder.encodeParameters(value: KeyAlgorithmIdentifier) {
        when (value) {
            is RsaKeyAlgorithmIdentifier     -> encodeParameters(NothingSerializer(), null) // explicit NULL per RSA
            is EcKeyAlgorithmIdentifier      -> encodeParameters(EcParameters.serializer(), value.parameters)
            is UnknownKeyAlgorithmIdentifier -> {
                // RFC 8410: parameters MUST be ABSENT for Ed25519/Ed448/X25519/X448
                if (value.algorithm.isRfc8410NoParams()) return
                when (val p = value.parameters) {
                    null        -> {
                        // For unknown algorithms, prefer ABSENT when no parameters provided
                        // (do nothing). If explicit NULL must be preserved, p will be Asn1Any(05 00).
                        return
                    }
                    is Asn1Any -> encodeParameters(Asn1Any.serializer(), p)
                    else       -> {
                        // Fallback: encode NULL to avoid guessing structure
                        encodeParameters(NothingSerializer(), null)
                    }
                }
            }
            else                             -> {
                // Safe default for other known types if any
                encodeParameters(NothingSerializer(), null)
            }
        }
    }

    override fun CompositeDecoder.decodeParameters(algorithm: ObjectIdentifier): KeyAlgorithmIdentifier = when (algorithm) {
        ObjectIdentifier.RSA -> {
            // null parameters
            decodeParameters<Nothing>(NothingSerializer())
            RsaKeyAlgorithmIdentifier
        }
        ObjectIdentifier.EC  -> EcKeyAlgorithmIdentifier(decodeParameters(EcParameters.serializer()))
        else                 -> {
            // Capture unknown parameters as raw ASN.1 for round-trip when present; null means ABSENT
            val raw: Asn1Any? = try {
                decodeParameters(Asn1Any.serializer())
            } catch (_: IllegalStateException) {
                // No element to read (ABSENT)
                null
            }
            UnknownKeyAlgorithmIdentifier(algorithm, raw)
        }
    }
}
