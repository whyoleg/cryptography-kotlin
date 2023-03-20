# JDK

> [API Reference](https://whyoleg.github.io/cryptography-kotlin/api/cryptography-jdk/index.html)

Provider implementation via
JDK built-in [JCA](https://docs.oracle.com/en/java/javase/17/security/java-cryptography-architecture-jca-reference-guide.html)
(javax.crypto.* / java.security.*)

For supported targets and algorithms please consult [Supported primitives section](index.md#supported-primitives)

## Limitations

* ECDSA: only `DER` signature format is supported for java < 9
* KeyFormat: doesn't support `JWK` key format yet
