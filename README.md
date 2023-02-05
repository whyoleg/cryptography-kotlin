# cryptography-kotlin

Types-safe Multiplatform cryptography library for Kotlin.

## Supported algorithms

|          | JDK    | WebCrypto | Apple  | OpenSSL3 |
|----------|--------|-----------|--------|----------|
| MD5      | ✅`h`   |           | ✅`h`   |          |
| SHA1     | ✅`h`   | ✅`h`      | ✅`h`   |          |
| SHA256   | ✅`h`   | ✅`h`      | ✅`h`   |          |
| SHA384   | ✅`h`   | ✅`h`      | ✅`h`   |          |
| SHA512   | ✅`h`   | ✅`h`      | ✅`h`   |          |
| AES-GCM  | ✅`e/d` | ✅`e/d`    |        |          |
| AES-CBC  | ✅`e/d` | ✅`e/d`    | ✅`e/d` |          |
| HMAC     | ✅`s/v` | ✅`s/v`    | ✅`s/v` |          |
| RSA-OAEP | ✅`e/d` | ✅`e/d`    |        |          |
| RSA-PSS  | ✅`s/v` | ✅`s/v`    |        |          |
| ECDSA    | ✅`s/v` | ✅`s/v`    |        |          |

> - `h` - hash
> - `e` - encryption
> - `d` - decryption
> - `s` - signing
> - `v` - verification
> - `a` - key agreement
