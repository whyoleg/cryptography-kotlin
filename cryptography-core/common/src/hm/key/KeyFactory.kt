package dev.whyoleg.cryptography.hm.key

public interface KeyFactory<GP, CP, IP, K> {
    public fun generate(parameters: GP): K

    //f.e. for RSA we can provide already generated exponent and modulus
    public fun create(parameters: CP): K

    public fun import(keyStore: KeyStore, parameters: IP): K
}

