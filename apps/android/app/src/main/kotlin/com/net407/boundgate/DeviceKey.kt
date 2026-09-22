package com.net407.boundgate

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/**
 * The device key: ECDSA P-256 in the Android Keystore, in StrongBox where the
 * phone has one, otherwise in the TEE. It never leaves the key store; the
 * core asks it to sign SHA-256 digests (NONEwithECDSA over the digest is
 * ECDSA over the message). A new identity is a new key: [delete] and start
 * again.
 */
class DeviceKey private constructor(private val key: PrivateKey, val publicKey: ByteArray, val kind: String, val hardwareBound: Boolean) {

    fun sign(digest: ByteArray): ByteArray {
        require(digest.size == 32) { "the core signs SHA-256 digests only" }
        return Signature.getInstance("NONEwithECDSA").run {
            initSign(key)
            update(digest)
            sign()
        }
    }

    companion object {
        private const val ALIAS = "boundgate-device"

        fun loadOrCreate(): DeviceKey {
            val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            if (!ks.containsAlias(ALIAS)) create()
            val entry = ks.getEntry(ALIAS, null) as KeyStore.PrivateKeyEntry
            val info = KeyFactory.getInstance(entry.privateKey.algorithm, "AndroidKeyStore")
                .getKeySpec(entry.privateKey, KeyInfo::class.java)
            val (kind, hw) = when (info.securityLevel) {
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> "android-strongbox" to true
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "android-keystore" to true
                // a key store without secure hardware: say so, the admin decides
                else -> "android-keystore-software" to false
            }
            return DeviceKey(entry.privateKey, entry.certificate.publicKey.encoded, kind, hw)
        }

        fun delete() {
            KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry(ALIAS)
        }

        private fun create() {
            fun spec(strongBox: Boolean) = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_NONE, KeyProperties.DIGEST_SHA256)
                .setIsStrongBoxBacked(strongBox)
                .build()
            val gen = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
            try {
                gen.initialize(spec(true))
                gen.generateKeyPair()
            } catch (e: Exception) {
                // no StrongBox (StrongBoxUnavailableException), or one that
                // refuses this key's parameters (ProviderException): the TEE
                if (e !is StrongBoxUnavailableException && e !is java.security.ProviderException) throw e
                gen.initialize(spec(false))
                gen.generateKeyPair()
            }
        }
    }
}
