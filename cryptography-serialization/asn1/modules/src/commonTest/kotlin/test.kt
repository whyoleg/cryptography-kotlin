/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1.modules

import dev.whyoleg.cryptography.serialization.asn1.*
import kotlin.random.*

private val s = SubjectPublicKeyInfo(
    algorithm = RsaKeyAlgorithmIdentifier,
    subjectPublicKey = BitArray(0, Random.nextBytes(10))
)

private val p = PrivateKeyInfo(
    version = 0,
    privateKeyAlgorithm = RsaKeyAlgorithmIdentifier,
    privateKey = Random.nextBytes(10)
)

//// DER encoding
//// TODO: better naming
//@ExperimentalCryptographySerializationApi
//public object PKCS8 {
//    public fun wrapPublicKey(
//        oid: String,
//        parameters: DerElement?,
//        publicKey: ByteArray,
//    ): ByteArray = DER.encodeToByteArray(
//        DerElement.Sequence(
//            arrayOf(
//                DerElement.Sequence(arrayOf(DerElement.ObjectIdentifier(oid), parameters)),
//                DerElement.BitString(publicKey)
//            )
//        )
//    )
//
//    public fun wrapPrivateKey(
//        version: Int,
//        oid: String,
//        parameters: DerElement?,
//        privateKey: ByteArray,
//    ): ByteArray = DER.encodeToByteArray(
//        DerElement.Sequence(
//            arrayOf(
//                DerElement.Integer(version),
//                DerElement.Sequence(arrayOf(DerElement.ObjectIdentifier(oid), parameters)),
//                DerElement.OctetString(privateKey)
//            )
//        )
//    )
//}
//
////
////private val OID_RSA = DerElement.OID("1.2.840.113549.1.1.1")
////private val NULL_PARAMETERS = null
////private val VERSION_0 = DerElement.Integer(0)
////
//@ExperimentalCryptographySerializationApi
//internal fun rsaPublicKeyToPKCS8(key: ByteArray): ByteArray =
//    PKCS8.wrapPublicKey(OID.RSA, null, key)
//
//@ExperimentalCryptographySerializationApi
//internal fun rsaPrivateKeyToPKCS8(key: ByteArray): ByteArray =
//    PKCS8.wrapPrivateKey(0, OID.RSA, null, key)
