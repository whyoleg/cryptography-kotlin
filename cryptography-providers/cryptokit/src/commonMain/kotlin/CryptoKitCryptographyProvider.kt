/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.cryptokit

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.cryptokit.algorithms.*
import dev.whyoleg.cryptography.providers.cryptokit.internal.swiftinterop.*
import kotlinx.cinterop.*

private val defaultProvider = lazy { CryptoKitCryptographyProvider }

public val CryptographyProvider.Companion.CryptoKit: CryptographyProvider by defaultProvider

@OptIn(UnsafeNumber::class)
internal object CryptoKitCryptographyProvider : CryptographyProvider() {
    override val name: String get() = "CryptoKit"

    @Suppress("UNCHECKED_CAST")
    override fun <A : CryptographyAlgorithm> getOrNull(identifier: CryptographyAlgorithmId<A>): A? = when (identifier) {
        MD5     -> CryptoKitDigest(MD5, SwiftHash::md5, SwiftHashAlgorithmMd5)
        SHA1    -> CryptoKitDigest(SHA1, SwiftHash::sha1, SwiftHashAlgorithmSha1)
        SHA256  -> CryptoKitDigest(SHA256, SwiftHash::sha256, SwiftHashAlgorithmSha256)
        SHA384  -> CryptoKitDigest(SHA384, SwiftHash::sha384, SwiftHashAlgorithmSha384)
        SHA512  -> CryptoKitDigest(SHA512, SwiftHash::sha512, SwiftHashAlgorithmSha512)
        HMAC    -> CryptoKitHmac
        HKDF    -> CryptoKitHkdf
        AES.GCM -> CryptoKitAesGcm
//        ECDSA   ->
//        ECDH   ->
        else    -> null
    } as A?
}

@Suppress("DEPRECATION")
@OptIn(ExperimentalStdlibApi::class)
@EagerInitialization
private val initHook = CryptographyProvider.Registry.registerProvider(defaultProvider)
