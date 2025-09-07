package dev.whyoleg.cryptography.providers.apple.keychain

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.storage.*
import kotlin.test.*

@OptIn(ExperimentalKeyStorageApi::class)
class AppleKeyStoreEcdsaTest {
    @Test
    fun generate_sign_verify_delete() {
        val label = "test-ecdsa-${kotlin.random.Random.nextInt()}".encodeToByteArray()
        val store = AppleKeyStore.ecdsa(EC.Curve.P256)
        assertFalse(store.exists(label))

        val h = store.generate(label, AccessPolicy())
        assertTrue(store.exists(label))

        val data = "hello-apple-keystore".encodeToByteArray()
        val gen = h.private.signatureGenerator(SHA256, ECDSA.SignatureFormat.DER)
        val ver = h.public.signatureVerifier(SHA256, ECDSA.SignatureFormat.DER)
        val sig = gen.createSignFunction().run {
            update(data, 0, data.size); signToByteArray()
        }
        val ok = ver.createVerifyFunction().run {
            update(data, 0, data.size); tryVerify(sig, 0, sig.size)
        }
        assertTrue(ok)

        assertTrue(store.delete(label))
        assertFalse(store.exists(label))
        assertNull(store.get(label))
    }
}

