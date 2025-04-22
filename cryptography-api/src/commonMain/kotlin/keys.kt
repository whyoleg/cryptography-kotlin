/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.api

// PEM in SPKI format
public interface PublicKey : PemEncodable

// PEM in PKCS8 format
public interface PrivateKey : PemEncodable

public interface PublicKeyFactory<K : PublicKey> : PemDecodable<K>

public interface PrivateKeyFactory<K : PrivateKey> : PemDecodable<K>

public class KeyPair<Pub : PublicKey, Pri : PrivateKey>(
    public val publicKey: Pub,
    public val privateKey: Pri,
)

public interface KeyPairGenerator<GP, Pub : PublicKey, Pri : PrivateKey> : GeneratePrimitive<GP, KeyPair<Pub, Pri>>
