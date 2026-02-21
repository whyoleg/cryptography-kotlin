/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import dev.whyoleg.cryptography.providers.openssl3.materials.*
import dev.whyoleg.cryptography.serialization.asn1.*
import dev.whyoleg.cryptography.serialization.asn1.modules.*
import kotlinx.cinterop.*
import platform.posix.*

internal abstract class Openssl3Ec<PublicK : EC.PublicKey, PrivateK : EC.PrivateKey<PublicK>, KP : EC.KeyPair<PublicK, PrivateK>>(
    private val wrapPublicKey: (EC.Curve, CPointer<EVP_PKEY>) -> PublicK,
    private val wrapPrivateKey: (EC.Curve, CPointer<EVP_PKEY>, PublicK?) -> PrivateK,
    private val wrapKeyPair: (PublicK, PrivateK) -> KP,
) : EC<PublicK, PrivateK, KP> {

    final override fun publicKeyDecoder(curve: EC.Curve): Decoder<EC.PublicKey.Format, PublicK> = EcPublicKeyDecoder(curve)

    final override fun privateKeyDecoder(curve: EC.Curve): Decoder<EC.PrivateKey.Format, PrivateK> = EcPrivateKeyDecoder(curve)

    final override fun keyPairGenerator(curve: EC.Curve): KeyGenerator<KP> = EcKeyGenerator(curve)

    private inner class EcPublicKeyDecoder(
        private val curve: EC.Curve,
    ) : Openssl3PublicKeyDecoder<EC.PublicKey.Format, PublicK>("EC") {
        override fun inputType(format: EC.PublicKey.Format): String = when (format) {
            EC.PublicKey.Format.DER -> "DER"
            EC.PublicKey.Format.PEM -> "PEM"
            EC.PublicKey.Format.RAW,
            EC.PublicKey.Format.RAW.Compressed,
            EC.PublicKey.Format.JWK,
                                    -> error("should not be called: handled explicitly in decodeFromBlocking")
        }

        override fun decodeFromByteArrayBlocking(format: EC.PublicKey.Format, bytes: ByteArray): PublicK = when (format) {
            EC.PublicKey.Format.RAW,
            EC.PublicKey.Format.RAW.Compressed,
                                    -> wrapKey(decodePublicRawKey(curve, bytes))
            EC.PublicKey.Format.JWK -> error("JWK format is not supported")
            else                    -> super.decodeFromByteArrayBlocking(format, bytes)
        }

        override fun wrapKey(key: CPointer<EVP_PKEY>): PublicK {
            EC_check_key_group(key, curve)
            return wrapPublicKey(curve, key)
        }

        @OptIn(UnsafeNumber::class)
        private fun decodePublicRawKey(curve: EC.Curve, input: ByteArray): CPointer<EVP_PKEY> = fromParameters {
            OSSL_PARAM_array(
                OSSL_PARAM_construct_utf8_string("group".cstr.ptr, curve.name.cstr.ptr, 0.convert()),
                OSSL_PARAM_construct_octet_string("pub".cstr.ptr, input.safeRefToU(0), input.size.convert())
            )
        }
    }

    private inner class EcPrivateKeyDecoder(
        private val curve: EC.Curve,
    ) : Openssl3PrivateKeyDecoder<EC.PrivateKey.Format, PrivateK>("EC") {
        override fun inputType(format: EC.PrivateKey.Format): String = when (format) {
            EC.PrivateKey.Format.DER, EC.PrivateKey.Format.DER.SEC1 -> "DER"
            EC.PrivateKey.Format.PEM, EC.PrivateKey.Format.PEM.SEC1 -> "PEM"
            EC.PrivateKey.Format.RAW, EC.PrivateKey.Format.JWK      -> "DER" // with custom processing
        }

        override fun inputStruct(format: EC.PrivateKey.Format): String = when (format) {
            EC.PrivateKey.Format.DER.SEC1, EC.PrivateKey.Format.PEM.SEC1 -> "EC"
            EC.PrivateKey.Format.RAW, EC.PrivateKey.Format.JWK           -> "EC" // with custom processing
            else                                                         -> super.inputStruct(format)
        }

        override fun decodeFromByteArrayBlocking(format: EC.PrivateKey.Format, bytes: ByteArray): PrivateK = when (format) {
            EC.PrivateKey.Format.RAW -> super.decodeFromByteArrayBlocking(format, convertPrivateRawKeyToSec1(curve, bytes))
            EC.PrivateKey.Format.JWK -> error("JWK format is not supported")
            else                     -> super.decodeFromByteArrayBlocking(format, bytes)
        }

        override fun wrapKey(key: CPointer<EVP_PKEY>): PrivateK {
            EC_check_key_group(key, curve)
            return wrapPrivateKey(curve, key, null)
        }

        // openssl doesn't infer a public key from a private key when decoding just a raw private key via `EVP_PKEY_fromdata;
        // so after decoding, we wrap it in SEC1 EcPrivateKey structure;
        // and import it via OSSL_DECODER as for other formats;
        // in this case, openssl INFER public key :)
        private fun convertPrivateRawKeyToSec1(curve: EC.Curve, input: ByteArray): ByteArray {
            return Der.encodeToByteArray(
                serializer = EcPrivateKey.serializer(),
                value = EcPrivateKey(
                    version = 1,
                    privateKey = input,
                    parameters = EcParameters(namedCurve = ObjectIdentifier(value = oid(curve)))
                )
            )
        }

        private fun oid(curve: EC.Curve): String = memScoped {
            val group = createEcGroup(curve.name)
            val groupId = checkError(EC_GROUP_get_curve_name(group))
            val oidObj = checkError(OBJ_nid2obj(groupId))
            // no_name = 1 means encode as "1.2.3" and not as a real name like secp521r1
            val length = checkError(OBJ_obj2txt(null, 0, oidObj, no_name = 1)) + 1
            val oidString = allocArray<ByteVar>(length)
            checkError(OBJ_obj2txt(oidString, length.convert(), oidObj, 1))
            oidString.toKString()
        }
    }

    private inner class EcKeyGenerator(
        private val curve: EC.Curve,
    ) : Openssl3KeyPairGenerator<KP>("EC") {
        @OptIn(UnsafeNumber::class)
        override fun MemScope.createParams(): CValuesRef<OSSL_PARAM>? = OSSL_PARAM_array(
            OSSL_PARAM_construct_utf8_string("group".cstr.ptr, curve.name.cstr.ptr, 0.convert())
        )

        override fun wrapKeyPair(keyPair: CPointer<EVP_PKEY>): KP {
            val publicKey = wrapPublicKey(curve, keyPair)
            val privateKey = wrapPrivateKey(curve, keyPair, publicKey)
            return wrapKeyPair(publicKey, privateKey)
        }
    }

    protected abstract inner class Openssl3EcPublicKey(
        protected val curve: EC.Curve,
        key: CPointer<EVP_PKEY>,
    ) : EC.PublicKey, Openssl3PublicKeyEncodable<EC.PublicKey.Format>(key) {
        override fun outputType(format: EC.PublicKey.Format): String = when (format) {
            EC.PublicKey.Format.DER -> "DER"
            EC.PublicKey.Format.PEM -> "PEM"
            EC.PublicKey.Format.RAW,
            EC.PublicKey.Format.RAW.Compressed,
            EC.PublicKey.Format.JWK,
                                    -> error("should not be called: handled explicitly in encodeToByteArrayBlocking")
        }

        override fun encodeToByteArrayBlocking(format: EC.PublicKey.Format): ByteArray = when (format) {
            EC.PublicKey.Format.RAW            -> encodePublicRawKey(key)
            EC.PublicKey.Format.RAW.Compressed -> encodePublicRawCompressedKey(key)
            EC.PublicKey.Format.JWK            -> error("JWK format is not supported")
            else                               -> super.encodeToByteArrayBlocking(format)
        }

        @OptIn(UnsafeNumber::class)
        private fun encodePublicRawCompressedKey(key: CPointer<EVP_PKEY>): ByteArray = memScoped {
            val group = createEcGroup(EC_group_name(key))
            val point = checkError(EC_POINT_new(group))
            try {
                val publicKey = encodePublicRawKey(key)
                // init EC_POINT
                checkError(EC_POINT_oct2point(group, point, publicKey.safeRefToU(0), publicKey.size.convert(), null))
                // get the size of a compressed point
                var outputSize = checkError(EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED, null, 0.convert(), null))
                val output = ByteArray(outputSize.convert())
                // encode compressed point
                outputSize = checkError(
                    EC_POINT_point2oct(
                        group = group,
                        p = point,
                        form = POINT_CONVERSION_COMPRESSED,
                        buf = output.safeRefToU(0),
                        len = outputSize.convert(),
                        ctx = null
                    )
                )
                output.ensureSizeExactly(outputSize.convert())
            } finally {
                EC_POINT_free(point)
            }
        }
    }

    protected abstract inner class Openssl3EcPrivateKey(
        protected val curve: EC.Curve,
        key: CPointer<EVP_PKEY>,
        publicKey: PublicK?,
    ) : EC.PrivateKey<PublicK>, Openssl3PrivateKeyEncodable<EC.PrivateKey.Format, PublicK>(key, publicKey) {
        final override fun wrapPublicKey(key: CPointer<EVP_PKEY>): PublicK = wrapPublicKey(curve, key)

        override fun outputType(format: EC.PrivateKey.Format): String = when (format) {
            EC.PrivateKey.Format.DER, EC.PrivateKey.Format.DER.SEC1 -> "DER"
            EC.PrivateKey.Format.PEM, EC.PrivateKey.Format.PEM.SEC1 -> "PEM"
            EC.PrivateKey.Format.RAW, EC.PrivateKey.Format.JWK      -> error("should not be called: handled explicitly in encodeToByteArrayBlocking")
        }

        override fun outputStruct(format: EC.PrivateKey.Format): String = when (format) {
            EC.PrivateKey.Format.DER.SEC1, EC.PrivateKey.Format.PEM.SEC1 -> "EC"
            else                                                         -> super.outputStruct(format)
        }

        override fun encodeToByteArrayBlocking(format: EC.PrivateKey.Format): ByteArray = when (format) {
            EC.PrivateKey.Format.RAW -> encodePrivateRawKey(key)
            EC.PrivateKey.Format.JWK -> error("JWK format is not supported")
            else                     -> super.encodeToByteArrayBlocking(format)
        }
    }

    @OptIn(UnsafeNumber::class)
    private fun encodePublicRawKey(key: CPointer<EVP_PKEY>): ByteArray = memScoped {
        val outVar = alloc<size_tVar>()
        checkError(EVP_PKEY_get_octet_string_param(key, "pub", null, 0.convert(), outVar.ptr))
        val output = ByteArray(outVar.value.convert())
        checkError(EVP_PKEY_get_octet_string_param(key, "pub", output.safeRefToU(0), output.size.convert(), outVar.ptr))
        output.ensureSizeExactly(outVar.value.convert())
    }

    private fun encodePrivateRawKey(key: CPointer<EVP_PKEY>): ByteArray = memScoped {
        val orderSize = EC_order_size(key)
        val privVar = alloc<CPointerVar<BIGNUM>>()
        checkError(EVP_PKEY_get_bn_param(key, "priv", privVar.ptr))
        val priv = checkError(privVar.value)
        val privateKey = ByteArray(orderSize)
        try {
            checkError(BN_bn2binpad(priv, privateKey.refToU(0), orderSize))
        } finally {
            BN_free(priv)
        }
        privateKey
    }

    @OptIn(UnsafeNumber::class)
    private fun EC_check_key_group(key: CPointer<EVP_PKEY>, expectedCurve: EC.Curve) = memScoped {
        val expectedGroup = createEcGroup(expectedCurve.name)
        // TODO: recheck this!!!
        val expectedGroupNid = checkError(EC_GROUP_get_curve_name(expectedGroup))
        val expectedGroupName = checkError(OSSL_EC_curve_nid2name(expectedGroupNid)).toKString()

        val keyGroupName = EC_group_name(key)

        check(expectedGroupName == keyGroupName) {
            "Wrong curve, expected ${expectedCurve.name}($expectedGroupName) actual $keyGroupName"
        }
    }

    protected fun EC_order_size(key: CPointer<EVP_PKEY>): Int = EC_order_size(EC_group_name(key))

    private fun EC_order_size(groupName: String): Int = memScoped {
        val group = createEcGroup(groupName)
        val order = checkError(BN_new())
        try {
            checkError(EC_GROUP_get_order(group, order, null))
            (checkError(BN_num_bits(order)) + 7) / 8
        } finally {
            BN_free(order)
        }
    }

    @OptIn(UnsafeNumber::class)
    private fun EC_group_name(key: CPointer<EVP_PKEY>): String = memScoped {
        val outputSize = alloc<size_tVar>()
        checkError(EVP_PKEY_get_utf8_string_param(key, "group", null, 0.convert(), outputSize.ptr))
        val groupNameSize = outputSize.value.toInt() + 1 // + 1 for null-termination
        val groupName = allocArray<ByteVar>(groupNameSize)
        checkError(EVP_PKEY_get_utf8_string_param(key, "group", groupName, groupNameSize.convert(), outputSize.ptr))
        groupName.toKString()
    }

    @OptIn(UnsafeNumber::class)
    private fun MemScope.createEcGroup(group: String): CPointer<EC_GROUP> {
        val group = checkError(
            EC_GROUP_new_from_params(
                params = OSSL_PARAM_array(
                    OSSL_PARAM_construct_utf8_string("group".cstr.ptr, group.cstr.ptr, 0.convert())
                ),
                libctx = null,
                propq = null
            )
        )
        defer { EC_GROUP_free(group) }
        return group
    }
}
