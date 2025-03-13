/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms.core.tests

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.DigestAlgorithm.Companion.Sha1
import dev.whyoleg.cryptography.algorithms.core.*
import kotlinx.io.bytestring.*
import kotlin.collections.get
import kotlin.invoke

private suspend fun test(digest: Digest) {
    digest.hash(
        "".encodeToByteString(),
        Unit
    )

    val hash = digest.createHashFunction(Sha1).use { function ->
        function.update("".encodeToByteString())
        function.hash()
    }
}

// can be generated
public fun EcPublicKey.Companion.decodeFromPem(text: String): EcPublicKey {
    return EcPublicKeyFactory().decodeFromPem(text)
}

// can be generated
public fun EcPublicKey.ecdsaVerifier(): EcdsaVerifier = EcdsaVerifier(this)

private fun test3(provider: CryptographyProvider) {
    val kp = EcKeyFactory().decodePublicKeyFromPem("")
    EcdsaVerifier(kp, EcdsaParameters(EcdsaSignatureFormat.DER))

    EcPublicKey.decodeFromPem("")
        .ecdsaVerifier()
        .verify("".encodeToByteString(), "".encodeToByteString(), Unit)



    when (val pub = GenericPublicKeyFactory().decodeFromPem("")) {
        is EcPublicKey -> {
        }
        // is RsaPublicKey
    }
    EcPublicKeyFactory().decodeFromPem("")

    val (pub, priv) = EcKeyFactory().generateKeyPair(EcCurve.P256)

    EcdsaSigner(priv, EcdsaParameters.DER)
        .sign("".encodeToByteString(), Unit)

    KeyPairGenerator(Ec(EcCurve.P256))

    EdKeyFactory()
    EdKeyFactory()






    Digest(Sha1)
    Digest.invoke(Sha1, provider)

    Hkdf(Sha1)
    provider.instantiate(Hkdf, HkdfParameters(Sha1))

//    providerBuilder.register(Hkdf) { parameters ->
//        // create hkdf instance
//    }

//    RsaPublicKeyFactory()
//        .decodeFromPem()
//        .instantiate(RsaOaep)

    Hkdf(Sha1)
    provider.instantiate(Digest, DigestParameters(Sha1))
    provider.instantiate(Hkdf, HkdfParameters(Sha1))

    val key = AesKeyFactory(Unit).generate()

    AesGcmCipher(key)
    val cipher = key.instantiate(AesGcmCipher, Unit)

    provider.instantiate(AesKeyFactory, Unit)
        .generate()
    provider.instantiate(EcPublicKeyFactory, Unit)
    provider.instantiate(EcKeyPairGenerator, Unit)
        .generate()

    AesGcmCipher(aesKey, PARAMETERS)

    val sha1 = Digest(Sha1, provider)

    sha1.hash("".encodeToByteString(), Unit)
    provider.instantiate(Digest, DigestParameters(Sha1))

    Hkdf(Sha1).deriveSecret(
        input = "".encodeToByteString(),
        parameters = HkdfDeriveParameters(
            outputSize = 10,
            salt = "".encodeToByteString()
        )
    )

    provider.get(
        tag = Digest,
        parameters = HashAlgorithm.Sha256
    )

    hmacKey.get(
        tag = Hmac,
        parameters = HashAlgorithm.Sha256
    )

    Digest(HashAlgorithm.Sha256)
        .hash("".encodeToByteString())

    HmacKeyDecoder().decode(key, hash)
    HmacKeyDecoder().generate(keySize, hash)

    val hmacKey = HmacKeyFactory(Sha1).generate(
        ...
    )

    Hmac(hmacKey)
        .computeMac("".encodeToByteString())
        .verifyMac("".encodeToByteString(), mac)

    Cmac(aesKey)


    val rsaKey = RsaPublicKeyFactory().decodeFromPem("")
    RsaPssVerifier(rsaKey, digest = SHA256, saltSize = 123).verify(

    )

    val ecKey = EcKeyPairGenerator().generate(EcCurve.P256)
    EcdsaSigner(ecKey.privateKey, SHA256).sign("".encodeToByteString())


    // new1
    provider
        .instantiate(EcKeyPairGenerator).generate(EcCurve.P256)
        .instantiate(EcdsaSigner, SHA256).sign("".encodeToByteString())

    // new2
    EcKeyPairGenerator().generate(EcCurve.P256).let {
        EcdsaSigner(it, SHA256).sign("".encodeToByteString())
    }

    // old
    provider.get(ECDSA)
        .keyPairGenerator(EcCurve.P256).generate()
        .signer(SHA256).sign("".encodeToByteString())
}

private fun testEc(provider: CryptographyProvider) {

    val keyPair = EcKeyPairGenerator().generate(
        EcKeyPairGeneratorParameters(
            EcCurve.P256
        )
    )

    EcPublicKeyFactory()
        .decodeFromPem("")

    keyPair
        .publicKey
        .encodeToPemString()
}

private fun test(provider: CryptographyProvider) {
    val key2 = AesKeyFactory()
        .generate(AesKeyGenerationParameters.B256)
    val cipher = AesGcmCipher(key2)

    val key =
        provider[AesKeyFactory].generate(AesKeyGenerationParameters.B256)

    val ciphertext = key[AesGcmCipher].encryptToBox(
        "".encodeToByteString()
    ).combined






    CryptographyProvider.Default.get(Sha1).hash("".encodeToByteString())
}

private suspend fun test2(crypto: CryptographyProvider) {
    //crypto.(Sha1).hash()

    Sha1().hash("".encodeToByteString())
    Sha1.Async().hash("".encodeToByteString())
    Sha1Digest().hash("".encodeToByteString())
    Sha1Digest.Async().hash("".encodeToByteString())

    crypto[Sha1].hash("".encodeToByteString())
    crypto[Sha1.Async].hash("".encodeToByteString())
    crypto[Sha1Digest].hash("".encodeToByteString())
    crypto[Sha1Digest.Async].hash("".encodeToByteString())

    crypto[Hkdf].deriveSecret(
        "".encodeToByteString(),
        HkdfParameters(
            Sha1Digest,
            10,
            ByteString()
        )
    )
    crypto[Hkdf].deriveSecret(
        "".encodeToByteString(),
        HkdfParameters(
            Sha1Digest,
            10,
            ByteString()
        )
    )

    Hkdf().deriveSecret(
        "".encodeToByteString(),
        HkdfParameters(
            Sha1Digest,
            10,
            ByteString()
        )
    )
}

internal fun hkdf(
    input: ByteString,
    // parameters
    digest: CryptographyProvider.Tag<SimpleDigest>,
    outputSize: Int,
    salt: ByteString,
    info: ByteString? = null,
): ByteString {
    val parameters = HkdfParameters(digest, outputSize, salt, info)
    return Hkdf().deriveSecret(input, parameters)
}

internal fun hkdf(
    input: ByteString,
    // parameters
    digest: CryptographyProvider.Tag<SimpleDigest>,
    outputSize: Int,
    salt: ByteString,
    info: ByteString? = null,
): ByteString {
    val parameters = HkdfParameters(digest, outputSize, salt, info)
    return Hkdf(parameters).deriveSecret(input, Unit)
}
