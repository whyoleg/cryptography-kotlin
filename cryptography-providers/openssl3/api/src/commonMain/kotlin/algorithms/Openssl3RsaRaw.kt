/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.algorithms.RSA
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.operations.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import dev.whyoleg.cryptography.providers.openssl3.operations.*
import kotlinx.cinterop.*
import kotlin.experimental.*

internal object Openssl3RsaRaw : Openssl3Rsa<RSA.RAW.PublicKey, RSA.RAW.PrivateKey, RSA.RAW.KeyPair>(), RSA.RAW {
    override fun wrapKeyPair(hashAlgorithm: String, keyPair: CPointer<EVP_PKEY>): RSA.RAW.KeyPair = RsaRawKeyPair(
        publicKey = RsaRawPublicKey(keyPair),
        privateKey = RsaRawPrivateKey(keyPair),
    )

    override fun wrapPublicKey(hashAlgorithm: String, publicKey: CPointer<EVP_PKEY>): RSA.RAW.PublicKey =
        RsaRawPublicKey(publicKey)

    override fun wrapPrivateKey(hashAlgorithm: String, privateKey: CPointer<EVP_PKEY>): RSA.RAW.PrivateKey =
        RsaRawPrivateKey(privateKey)

    private class RsaRawKeyPair(
        override val publicKey: RSA.RAW.PublicKey,
        override val privateKey: RSA.RAW.PrivateKey,
    ) : RSA.RAW.KeyPair

    private class RsaRawPublicKey(
        key: CPointer<EVP_PKEY>,
    ) : RsaPublicKey(key), RSA.RAW.PublicKey {
        override fun encryptor(): Encryptor = RsaRawEncryptor(key)
    }

    private class RsaRawPrivateKey(
        key: CPointer<EVP_PKEY>,
    ) : RsaPrivateKey(key), RSA.RAW.PrivateKey {
        override fun decryptor(): Decryptor = RsaRawDecryptor(key)
    }
}

private class RsaRawEncryptor(
    private val publicKey: CPointer<EVP_PKEY>,
) : BaseEncryptor {
    @OptIn(ExperimentalNativeApi::class)
    private val cleaner = publicKey.upRef().cleaner()

    @OptIn(UnsafeNumber::class)
    override fun createEncryptFunction(): CipherFunction {
        return EvpPKeyCipherFunction(publicKey, encrypt = true) {
            OSSL_PARAM_arrayNotNull(
                OSSL_PARAM_construct_utf8_string("pad-mode".cstr.ptr, "none".cstr.ptr, 0.convert()),
            )
        }
    }
}

private class RsaRawDecryptor(
    private val privateKey: CPointer<EVP_PKEY>,
) : BaseDecryptor {
    @OptIn(ExperimentalNativeApi::class)
    private val cleaner = privateKey.upRef().cleaner()

    @OptIn(UnsafeNumber::class)
    override fun createDecryptFunction(): CipherFunction {
        return EvpPKeyCipherFunction(privateKey, encrypt = false) {
            OSSL_PARAM_arrayNotNull(
                OSSL_PARAM_construct_utf8_string("pad-mode".cstr.ptr, "none".cstr.ptr, 0.convert()),
            )
        }
    }
}
