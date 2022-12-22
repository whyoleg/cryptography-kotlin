package dev.whyoleg.cryptography.algorithms.asymmetric


public object RSA {
    public object OAEP {
        public interface PublicKey

        public interface PrivateKey {
            public val publicKey: PublicKey
        }

        public interface KeyPair {
            public val publicKey: PublicKey
            public val privateKey: PrivateKey
        }
    }
}
