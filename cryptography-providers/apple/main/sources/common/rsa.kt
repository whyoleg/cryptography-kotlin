package dev.whyoleg.cryptography.apple

import kotlinx.cinterop.*
import platform.CoreFoundation.*
import platform.Foundation.*
import platform.Security.*
import platform.darwin.*

private fun test() {
    memScoped {
        val publicKeyAttr = CFDictionaryCreateMutable(null, 2, null, null)
        CFDictionaryAddValue(publicKeyAttr, kSecAttrIsPermanent, CFBridgingRetain(NSNumber(bool = false)))
        CFDictionaryAddValue(
            publicKeyAttr, kSecAttrApplicationTag,
            CFBridgingRetain(NSData.dataWithBytes(bytes = "com.foo.public".cstr.ptr, length = 15u))
        )
        val privateKeyAttr = CFDictionaryCreateMutable(null, 2, null, null)
        CFDictionaryAddValue(privateKeyAttr, kSecAttrIsPermanent, CFBridgingRetain(NSNumber(bool = false)))
        CFDictionaryAddValue(
            privateKeyAttr, kSecAttrApplicationTag,
            CFBridgingRetain(NSData.dataWithBytes(bytes = "com.foo.private".cstr.ptr, length = 16u))
        )
        val keyPairAttr = CFDictionaryCreateMutable(null, 4, null, null)
        CFDictionaryAddValue(keyPairAttr, kSecAttrKeyType, kSecAttrKeyTypeRSA)
        CFDictionaryAddValue(keyPairAttr, kSecAttrKeySizeInBits, CFBridgingRetain(NSNumber(int = 2048)))
        CFDictionaryAddValue(keyPairAttr, kSecPublicKeyAttrs, publicKeyAttr)
        CFDictionaryAddValue(keyPairAttr, kSecPrivateKeyAttrs, privateKeyAttr)
        var publicKey = alloc<SecKeyRefVar>()
        var privateKey = alloc<SecKeyRefVar>()
        val statusCode = SecKeyGeneratePair(keyPairAttr, publicKey.ptr, privateKey.ptr)

        if (statusCode == noErr.toInt() && publicKey.value != null && privateKey.value != null) {
            val error1 = alloc<CFErrorRefVar>()
            val error2 = alloc<CFErrorRefVar>()
            val publicExternal = SecKeyCopyExternalRepresentation(publicKey.value, error1.ptr)
            val privateExternal = SecKeyCopyExternalRepresentation(privateKey.value, error2.ptr)
            if (error1.value == null && error2.value == null) {
                val pubKey = CFBridgingRelease(publicExternal) as NSData
                val privKey = CFBridgingRelease(privateExternal) as NSData
                println("generated keypair OK: public=$pubKey private=$privKey")
            }
        } else {
            println("cannot generate keypair: $statusCode")
        }

        CFBridgingRelease(publicKeyAttr)
        CFBridgingRelease(privateKeyAttr)
        CFBridgingRelease(keyPairAttr)
    }
}
