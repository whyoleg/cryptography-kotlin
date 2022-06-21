package dev.whyoleg.cryptography.algorithms.aes

import dev.whyoleg.bignumber.*
import dev.whyoleg.cryptography.new.*
import dev.whyoleg.cryptography.new.cipher.*
import dev.whyoleg.cryptography.new.key.*
import dev.whyoleg.vio.*
import kotlin.jvm.*

public object Aes {
    public val gcm: Gcm = Gcm

    public object Gcm
}

public class AesGcmBox(
    public val initializationVector: InitializationVector,
    ciphertext: Ciphertext,
    public val authTag: AuthTag
) : CipherBox(ciphertext)

public class AesGcmCipherParameters(
    public val padding: Boolean,
    public val tagSize: BinarySize,
) : CipherParameters

public interface AesMaterial : CipherMaterial

public enum class AesGenerationParameters : GenerationParameters {
    AES128, AES192, AES256;
}

public object AesGenerationMarker : GenerationMarker<AesGenerationParameters, AesMaterial>

public sealed interface AesGcmEncryptMarker<T : Encryptor> :
    EncryptMarker<AesMaterial, AesGcmCipherParameters, T> {
    public object Sync : AesGcmEncryptMarker<AesGcmCipherPrimitive.Sync>
    public object Async : AesGcmEncryptMarker<AesGcmCipherPrimitive.Async>
    public object Function : AesGcmEncryptMarker<AesGcmCipherPrimitive.Function>
}

public sealed interface AesGcmCipherPrimitive {
    public interface Sync : SyncContextCipherPrimitive<AesGcmBox, AssociatedData>
    public interface Async : AsyncContextCipherPrimitive<AesGcmBox, AssociatedData>
    public interface Function : FunctionContextCipherPrimitive<AssociatedData>
}


private fun test(
    generateProvider: GenerationProvider,
    encryptProvider: EncryptProvider,
) {
    with(generateProvider) {
        with(encryptProvider) {


            val generator = RsaKeyPairGenerator {
                modulusLength(2048.bits)
            }

            val keyPair = generator.generateKeyPair()

            val encryptor = RsaOaepEncryptor(keyPair.publicKey) {
                digest(Sha256Digest())
            }


            val key = RSA.keyPair.generate()
            RSA.keyPair.encode(key, KeyFormat.PKCS12)
            RSA.keyPair.encode(key, KeyFormat.JWK)
            RSA.keyPair.decode(plainKey, KeyFormat.JWK)
            RSA.publicKey.decode(plainKey, KeyFormat.DER)
            RSA.privateKey.import(plainKey, KeyFormat.PEM)

            val generator = RsaKeyPairGenerator()
            val generator = RsaKeyPairAsyncGenerator()

            RsaKeyPairDecoder()
            RsaKeyPairAsyncDecoder()
            RsaKeyPairStreamDecoder()

            AesGcmAsyncCipher()
            AesGcmStreamEncrypter()

            AesGcmCipher()
            AesKeyGenerator()
            AesKeyEncoder()
            AesKeyDecoder()

            AesGcmAsyncCipher()
            AesGcmStreamCipher().encrypt {
                encryptPart()
            }

            Sha1Digest()

            Md5Digest()

            HmacKeyGenerator {
                digest(Sha1Digest.Parameters())
            }


            Shake128Digest {
                outputSize(16.bytes)
            }

            val keyPair = generator.generate {
                keySize(2048.bits)
            }

            RsaOaepAsyncEncryptor(key.publicKey) {

            }

            val encryptor = RSA.OAEP.encryptor.async(key.publicKey) {
                hash(SHA.SHA3_256)
            }

            encryptor.encrypr()

            val key = Aes.generateKey {
                size(128.bits)
            }

            val cipher = Aes.gcm.cipher.async(key) {
                padding(true)
                tagSize(12.bytes)
            }

            val cipher = AesGcmEncryptMarker.Async(
                key,
                AesGcmCipherParameters(padding = true, tagSize = 12.bytes)
            )
            val ciphertext = cipher.encrypt(
                AssociatedData("test".encodeToByteArray().view()),
                Plaintext("test".encodeToByteArray().view()),
            )
            val decrypted = cipher.decrypt(
                AssociatedData("test".encodeToByteArray().view()),
                ciphertext,
            )
            println(decrypted)
        }
    }
}

@JvmInline
public value class SecretKeyMaterial(
    public val value: BufferView
) : CryptographyMaterial


public sealed interface RsaMaterial : CryptographyMaterial {
    public val publicExponent: BigInt
    public val modulusLength: BinarySize
}

public interface RsaHashedKeyMaterial : RsaMaterial {
    public val hash: HashParameters
    override val publicExponent: BigInt
    override val modulusLength: BinarySize
}

public class RsaHashedPrivateKeyMaterial(
    override val publicExponent: BigInt,
    override val modulusLength: BinarySize,
    public val hash: HashParameters
) : RsaMaterial

public class RsaHashedPublicKeyMaterial(
    override val publicExponent: BigInt,
    override val modulusLength: BinarySize,
    public val hash: HashParameters
) : RsaMaterial

public class RsaPrivateKeyMaterial(
    override val publicExponent: BigInt,
    override val modulusLength: BinarySize,
    //other fields
) : RsaMaterial

public class RsaPublicKeyMaterial(
    override val publicExponent: BigInt,
    override val modulusLength: BinarySize,
) : RsaMaterial