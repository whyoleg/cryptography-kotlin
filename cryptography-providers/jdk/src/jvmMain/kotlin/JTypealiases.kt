/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk

import java.security.*
import javax.crypto.*

internal typealias JCipher = Cipher
internal typealias JKeyGenerator = KeyGenerator
internal typealias JKeyPairGenerator = KeyPairGenerator
internal typealias JKeyPair = KeyPair
internal typealias JPrivateKey = PrivateKey
internal typealias JPublicKey = PublicKey
internal typealias JSecretKey = SecretKey
internal typealias JSecretKeyFactory = SecretKeyFactory
internal typealias JKey = Key
internal typealias JMessageDigest = MessageDigest
internal typealias JMac = Mac
internal typealias JProvider = Provider
internal typealias JSignature = Signature
internal typealias JSecureRandom = SecureRandom
internal typealias JKeyFactory = KeyFactory
internal typealias JAlgorithmParameters = AlgorithmParameters
internal typealias JAlgorithmParameterGenerator = AlgorithmParameterGenerator
internal typealias JKeyAgreement = KeyAgreement
