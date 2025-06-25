/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import dev.whyoleg.cryptography.serialization.asn1.*
import dev.whyoleg.cryptography.serialization.asn1.modules.*
import kotlinx.cinterop.*
import platform.posix.*

@OptIn(UnsafeNumber::class)
internal fun decodePublicRawKey(
    curve: EC.Curve,
    input: ByteArray,
): CPointer<EVP_PKEY> = memScoped {
    val context = checkError(EVP_PKEY_CTX_new_from_name(null, "EC", null))
    try {
        checkError(EVP_PKEY_fromdata_init(context))
        val pkeyVar = alloc<CPointerVar<EVP_PKEY>>()
        checkError(
            EVP_PKEY_fromdata(
                ctx = context,
                ppkey = pkeyVar.ptr,
                selection = EVP_PKEY_PUBLIC_KEY,
                param = OSSL_PARAM_array(
                    OSSL_PARAM_construct_utf8_string("group".cstr.ptr, curve.name.cstr.ptr, 0.convert()),
                    OSSL_PARAM_construct_octet_string("pub".cstr.ptr, input.safeRefToU(0), input.size.convert())
                )
            )
        )
        checkError(pkeyVar.value)
    } finally {
        EVP_PKEY_CTX_free(context)
    }
}

@OptIn(UnsafeNumber::class)
internal fun convertPrivateRawKeyToSec1(
    curve: EC.Curve,
    input: ByteArray,
): ByteArray = memScoped {
    val context = checkError(EVP_PKEY_CTX_new_from_name(null, "EC", null))
    try {
        checkError(EVP_PKEY_fromdata_init(context))
        val pkeyVar = alloc<CPointerVar<EVP_PKEY>>()
        checkError(
            EVP_PKEY_fromdata(
                ctx = context,
                ppkey = pkeyVar.ptr,
                selection = EVP_PKEY_PRIVATE_KEY,
                param = OSSL_PARAM_array(
                    OSSL_PARAM_construct_utf8_string("group".cstr.ptr, curve.name.cstr.ptr, 0.convert()),
                    OSSL_PARAM_construct_BN("priv".cstr.ptr, input.safeRefToU(0), input.size.convert())
                )
            )
        )
        val privateKey = checkError(pkeyVar.value)

        // openssl doesn't infer a public key from a private key when decoding just a raw private key;
        // so after decoding, we wrap it in SEC1 EcPrivateKey structure;
        // and import it via OSSL_DECODER as for other formats;
        // in this case, openssl INFER public key :)

        // we use privateKey only to get OID,
        // as `group` openssl supports aliases for `group` in EVP_PKEY_fromdata, like P-521 for secp521r1
        // but has no API to get OID from it directly

        try {
            val groupId = checkError(OBJ_sn2nid(EC_group_name(privateKey)))
            val oidObj = checkError(OBJ_nid2obj(groupId))
            // no_name = 1 means encode as "1.2.3" and not as a real name like secp521r1
            val length = checkError(OBJ_obj2txt(null, 0, oidObj, no_name = 1)) + 1
            val oidString = allocArray<ByteVar>(length)
            checkError(OBJ_obj2txt(oidString, length.convert(), oidObj, 1))
            val parameters = EcParameters(ObjectIdentifier(oidString.toKString()))
            Der.encodeToByteArray(
                EcPrivateKey.serializer(),
                EcPrivateKey(1, input, parameters)
            )
        } finally {
            EVP_PKEY_free(privateKey)
        }
    } finally {
        EVP_PKEY_CTX_free(context)
    }
}

@OptIn(UnsafeNumber::class)
internal fun encodePublicRawKey(key: CPointer<EVP_PKEY>): ByteArray = memScoped {
    val outVar = alloc<size_tVar>()
    checkError(EVP_PKEY_get_octet_string_param(key, "encoded-pub-key", null, 0.convert(), outVar.ptr))
    val output = ByteArray(outVar.value.convert())
    checkError(EVP_PKEY_get_octet_string_param(key, "encoded-pub-key", output.safeRefToU(0), output.size.convert(), outVar.ptr))
    output.ensureSizeExactly(outVar.value.convert())
}

/**
 * Encodes a public key to compressed point format.
 * 
 * Note: We manually implement point compression instead of using the deprecated OpenSSL EC_* APIs
 * (EVP_PKEY_get1_EC_KEY, EC_KEY_get0_group, EC_POINT_point2oct with POINT_CONVERSION_COMPRESSED)
 * to stay compatible with OpenSSL 3.0+ where those methods are deprecated in favor of EVP_PKEY_* APIs.
 * 
 * @see <a href="https://docs.openssl.org/master/man3/EVP_PKEY_set1_RSA">OpenSSL Documentation</a>
 */
@OptIn(UnsafeNumber::class)
internal fun encodePublicRawCompressedKey(key: CPointer<EVP_PKEY>): ByteArray = memScoped {
    // coordinate size for this curve
    val coordinateSize = EC_order_size(key)
    val expectedCompressedSize = coordinateSize + 1
    val expectedUncompressedSize = 2 * coordinateSize + 1
    
    // uncompressed public key point
    val uncompressedSize = alloc<size_tVar>()
    checkError(EVP_PKEY_get_octet_string_param(key, "pub", null, 0.convert(), uncompressedSize.ptr))
    val uncompressed = ByteArray(uncompressedSize.value.convert())
    checkError(EVP_PKEY_get_octet_string_param(key, "pub", uncompressed.safeRefToU(0), uncompressed.size.convert(), uncompressedSize.ptr))

    // already compressed
    if (uncompressed.size == expectedCompressedSize && (uncompressed[0] == 0x02.toByte() || uncompressed[0] == 0x03.toByte())) {
        uncompressed
    }
    // standard uncompressed format (0x04 + X + Y)
    else if (uncompressed.size == expectedUncompressedSize && uncompressed[0] == 0x04.toByte()) {
        val compressed = ByteArray(expectedCompressedSize)
        // Copy X coordinate (bytes 1 to coordinateSize)
        uncompressed.copyInto(compressed, 1, 1, coordinateSize + 1)
        val yLastByte = uncompressed[expectedUncompressedSize - 1] // Last byte of Y coordinate
        compressed[0] = if ((yLastByte.toInt() and 1) == 0) 0x02.toByte() else 0x03.toByte()
        compressed
    }
    // For other formats, return uncompressed
    else {
        uncompressed
    }
}

internal fun encodePrivateRawKey(key: CPointer<EVP_PKEY>): ByteArray = memScoped {
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
internal fun EC_check_key_group(key: CPointer<EVP_PKEY>, expectedCurve: EC.Curve) = memScoped {
    //we need to construct a group, because our EC.Curve names are not the ones, which are used inside openssl
    val expectedGroup = checkError(
        EC_GROUP_new_from_params(
            OSSL_PARAM_array(
                OSSL_PARAM_construct_utf8_string("group".cstr.ptr, expectedCurve.name.cstr.ptr, 0.convert())
            ), null, null
        )
    )
    try {
        val expectedGroupNid = checkError(EC_GROUP_get_curve_name(expectedGroup))
        val expectedGroupName = checkError(OSSL_EC_curve_nid2name(expectedGroupNid)).toKString()

        val keyGroupName = allocArray<ByteVar>(256).also {
            checkError(EVP_PKEY_get_utf8_string_param(key, "group", it, 256.convert(), null))
        }.toKString()

        check(expectedGroupName == keyGroupName) {
            "Wrong curve, expected ${expectedCurve.name}($expectedGroupName) actual $keyGroupName"
        }
    } finally {
        EC_GROUP_free(expectedGroup)
    }
}

internal fun EC_order_size(key: CPointer<EVP_PKEY>): Int = memScoped {
    val orderVar = alloc<CPointerVar<BIGNUM>>()
    checkError(EVP_PKEY_get_bn_param(key, "order", orderVar.ptr))
    val order = checkError(orderVar.value)
    try {
        (checkError(BN_num_bits(order)) + 7) / 8
    } finally {
        BN_free(order)
    }
}

@OptIn(UnsafeNumber::class)
internal fun EC_group_name(key: CPointer<EVP_PKEY>): String = memScoped {
    val outputSize = alloc<size_tVar>()
    checkError(EVP_PKEY_get_utf8_string_param(key, "group", null, 0.convert(), outputSize.ptr))
    val groupNameSize = outputSize.value.toInt() + 1
    val groupName = allocArray<ByteVar>(groupNameSize)
    checkError(EVP_PKEY_get_utf8_string_param(key, "group", groupName, groupNameSize.convert(), outputSize.ptr))
    groupName.toKString()
}
