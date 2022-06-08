package dev.whyoleg.cryptography.jwk

import kotlin.jvm.*

//requires kotlinx.datetime and kotlinx.serialization
public sealed class JsonWebKey(
    public val algorithm: Algorithm,
    public val usage: Usage?,
    public val keyId: KeyId?
) {
    public sealed class Algorithm(public val value: String) {
        public object EC : Algorithm("EC")
        public object RSA : Algorithm("RSA")
        public class Custom(value: String) : Algorithm(value)
    }

    public sealed class Usage(public val value: String) {
        public object Signature : Usage("sig")
        public object Encryption : Usage("enc")
        public class Custom(value: String) : Usage(value)
    }

    @JvmInline
    public value class KeyId(public val value: String)

    public class EC(
        public val curve: Curve,
        public val x: String, //base64url
        public val y: String, //base64url
        usage: Usage? = null,
        keyId: KeyId? = null
    ) : JsonWebKey(Algorithm.EC, usage, keyId) {
        public sealed class Curve(public val value: String) {
            public object P256 : Curve("P-256")
            public object P384 : Curve("P-384")
            public object P521 : Curve("P-521")
            public class Custom(value: String) : Curve(value)
        }
    }

    public class RSA(
        public val modulus: String, //base64url
        public val exponent: String, //base64url
        usage: Usage? = null,
        keyId: KeyId? = null
    ) : JsonWebKey(Algorithm.RSA, usage, keyId)

    //TODO: how to support it serialization?
    public abstract class Custom(
        algorithm: Algorithm.Custom,
        usage: Usage? = null,
        keyId: KeyId? = null
    ) : JsonWebKey(algorithm, usage, keyId)
}

