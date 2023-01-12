package dev.whyoleg.cryptography.webcrypto

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.algorithms.asymmetric.ec.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.algorithms.symmetric.mac.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.provider.*
import dev.whyoleg.cryptography.webcrypto.algorithms.*

public val CryptographyProvider.Companion.WebCrypto: CryptographyProvider get() = WebCryptoCryptographyProvider

//Not yet implemented: HKDF, PBKDF2, RSASSA-PKCS1-v1_5, AES-KW
//PEM support
internal object WebCryptoCryptographyProvider : CryptographyProvider() {
    override val name: String get() = "WebCrypto"

    @Suppress("UNCHECKED_CAST")
    override fun <A : CryptographyAlgorithm> getOrNull(identifier: CryptographyAlgorithmId<A>): A? = when (identifier) {
        SHA1     -> WebCryptoDigest.SHA1
        SHA256   -> WebCryptoDigest.SHA256
        SHA384   -> WebCryptoDigest.SHA384
        SHA512   -> WebCryptoDigest.SHA512
        HMAC     -> WebCryptoHmac
        AES.CBC  -> WebCryptoAesCbc
        AES.GCM  -> WebCryptoAesGcm
        RSA.OAEP -> WebCryptoRsaOaep
        RSA.PSS  -> WebCryptoRsaPss
        ECDH     -> WebCryptoEcdh
        ECDSA    -> WebCryptoEcdsa
        else     -> null
    } as A?
}

@Suppress("DEPRECATION", "INVISIBLE_MEMBER")
@OptIn(ExperimentalStdlibApi::class, ExperimentalJsExport::class)
@EagerInitialization
@JsExport
@Deprecated("", level = DeprecationLevel.HIDDEN)
public val initHook: dynamic = registerProvider { WebCryptoCryptographyProvider }
