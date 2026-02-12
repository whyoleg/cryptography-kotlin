package dev.whyoleg.cryptography.storage

import kotlin.test.*

@OptIn(ExperimentalKeyStorageApi::class)
class StorageApiSmokeTest {
    @Test
    fun accessPolicy_defaults() {
        val p = AccessPolicy()
        assertFalse(p.requireUserPresence)
        assertEquals(Accessibility.AfterFirstUnlock, p.accessibility)
        assertEquals(DeviceBinding.None, p.deviceBinding)
        assertFalse(p.exportablePrivate)
    }

    @Test
    fun asymmetric_store_basic_crud() {
        class InMemoryAsym<Pub, Priv> : AsymmetricStore<Pub, Priv> {
            private val map = mutableMapOf<String, Handle<Pub, Priv>>()
            override fun generate(label: ByteArray, access: AccessPolicy): Handle<Pub, Priv> {
                error("not implemented: provide generator in test")
            }

            fun generateWith(label: ByteArray, access: AccessPolicy, generator: (String) -> Handle<Pub, Priv>): Handle<Pub, Priv> {
                val k = label.decodeToString()
                val h = generator(k)
                map[k] = h
                return h
            }

            override fun get(label: ByteArray): Handle<Pub, Priv>? = map[label.decodeToString()]
            override fun exists(label: ByteArray): Boolean = map.containsKey(label.decodeToString())
            override fun delete(label: ByteArray): Boolean = map.remove(label.decodeToString()) != null
        }

        val store = InMemoryAsym<String, String>()
        val label = "wallet-ed25519"
        assertFalse(store.exists(label.encodeToByteArray()))

        val generated = store.generateWith(label.encodeToByteArray(), AccessPolicy()) { k ->
            Handle(
                public = "PUB:$k",
                private = "PRIV:$k",
                attributes = KeyAttributes(extractable = false, persistent = true, label = k.encodeToByteArray())
            )
        }
        assertEquals("PUB:$label", generated.public)
        assertTrue(store.exists(label.encodeToByteArray()))

        val fetched = store.get(label.encodeToByteArray())
        assertNotNull(fetched)
        assertEquals(generated.public, fetched.public)
        assertEquals(generated.private, fetched.private)

        assertTrue(store.delete(label.encodeToByteArray()))
        assertFalse(store.exists(label.encodeToByteArray()))
        assertNull(store.get(label.encodeToByteArray()))
    }

    @Test
    fun symmetric_store_basic_crud() {
        class InMemorySym<K> : SymmetricStore<K> {
            private val map = mutableMapOf<String, Handle<K, Unit>>()
            override fun generate(label: ByteArray, access: AccessPolicy): Handle<K, Unit> {
                error("not implemented: provide generator in test")
            }

            fun generateWith(label: ByteArray, access: AccessPolicy, generator: (String) -> Handle<K, Unit>): Handle<K, Unit> {
                val k = label.decodeToString()
                val h = generator(k)
                map[k] = h
                return h
            }

            override fun get(label: ByteArray): Handle<K, Unit>? = map[label.decodeToString()]
            override fun exists(label: ByteArray): Boolean = map.containsKey(label.decodeToString())
            override fun delete(label: ByteArray): Boolean = map.remove(label.decodeToString()) != null
        }

        val store = InMemorySym<String>()
        val label = "aes-gcm-key"
        assertFalse(store.exists(label.encodeToByteArray()))
        val generated = store.generateWith(label.encodeToByteArray(), AccessPolicy()) { k ->
            Handle(
                public = "K:$k",
                private = Unit,
                attributes = KeyAttributes(extractable = false, persistent = true, label = k.encodeToByteArray())
            )
        }
        assertEquals("K:$label", generated.public)
        assertTrue(store.exists(label.encodeToByteArray()))
        assertNotNull(store.get(label.encodeToByteArray()))
        assertTrue(store.delete(label.encodeToByteArray()))
        assertFalse(store.exists(label.encodeToByteArray()))
    }
}

