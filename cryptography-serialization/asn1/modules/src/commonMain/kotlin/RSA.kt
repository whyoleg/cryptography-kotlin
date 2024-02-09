/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1.modules

import dev.whyoleg.cryptography.bigint.*
import kotlinx.serialization.*

@Serializable
public class RsaPssKeyAlgorithmParameters(
    public val hashAlgorithm: HashAlgorithmIdentifier,
    public val maskGenAlgorithm: MaskGenAlgorithmIdentifier,
    public val saltLength: Int = 20,
    public val trailerField: Int = 1,
)

@Serializable
public class RsaOaepKeyAlgorithmParameters(
    public val hashFunc: HashAlgorithmIdentifier,
    public val maskGenFunc: MaskGenAlgorithmIdentifier,
    public val pSourceFunc: PSourceAlgorithmIdentifier = PSourceAlgorithmIdentifier(ByteArray(0)), // TODO
)

//      -- AlgorithmIdentifier parameters for id-RSAES-OAEP.
//      -- Note that the tags in this Sequence are explicit.
//
//      RSAES-OAEP-params  ::=  SEQUENCE  {
//         hashFunc          [0] AlgorithmIdentifier DEFAULT sha1Identifier,
//         maskGenFunc       [1] AlgorithmIdentifier DEFAULT mgf1SHA1Identifier,
//         pSourceFunc       [2] AlgorithmIdentifier DEFAULT pSpecifiedEmptyIdentifier  }

@Serializable
public class RsaPublicKey(
    public val modulus: BigInt,
    public val publicExponent: BigInt,
)

//RSAPrivateKey ::= SEQUENCE {
//      version   Version,
//      modulus   INTEGER,  -- n
//      publicExponent    INTEGER,  -- e
//      privateExponent   INTEGER,  -- d
//      prime1INTEGER,  -- p
//      prime2INTEGER,  -- q
//      exponent1 INTEGER,  -- d mod (p-1)
//      exponent2 INTEGER,  -- d mod (q-1)
//      coefficient   INTEGER,  -- (inverse of q) mod p
//      otherPrimeInfos   OtherPrimeInfos OPTIONAL
//    }

//https://datatracker.ietf.org/doc/html/rfc5280
//https://datatracker.ietf.org/doc/html/rfc4055#section-3.1
//https://datatracker.ietf.org/doc/html/rfc4491
//https://www.ietf.org/rfc/rfc3279.txt
//https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der/#object-identifier
//https://mbed-tls.readthedocs.io/en/latest/kb/cryptography/asn1-key-structures-in-der-and-pem/
