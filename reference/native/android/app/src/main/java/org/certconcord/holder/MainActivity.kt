package org.certconcord.holder

import android.app.Activity
import android.os.Bundle
import android.os.CancellationSignal
import android.hardware.biometrics.BiometricPrompt
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.KeyInfo
import android.widget.*
import android.view.WindowManager
import java.security.*
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import org.json.JSONObject

class AndroidHolderKey {
    private val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private fun alias(value: String): String { require(Regex("certconcord-[A-Za-z0-9_-]{8,100}").matches(value)); return value }
    fun generate(name: String, challenge: ByteArray, strongBox: Boolean): JSONObject {
        require(challenge.size in 32..128 && !store.containsAlias(alias(name)))
        val builder = KeyGenParameterSpec.Builder(name, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1")).setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(true).setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            .setInvalidatedByBiometricEnrollment(true).setAttestationChallenge(challenge).setIsStrongBoxBacked(strongBox)
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").apply { initialize(builder.build()); generateKeyPair() }
        return publicInfo(name)
    }
    fun publicInfo(name: String): JSONObject {
        val key = store.getCertificate(alias(name)).publicKey as ECPublicKey
        fun coordinate(v: java.math.BigInteger): String { val raw = v.toByteArray(); val out = ByteArray(32); val n = minOf(32, raw.size); System.arraycopy(raw, raw.size - n, out, 32 - n, n); return b64(out) }
        val privateKey = store.getKey(name, null) as PrivateKey
        val info = KeyFactory.getInstance(privateKey.algorithm, "AndroidKeyStore").getKeySpec(privateKey, KeyInfo::class.java)
        return JSONObject().put("jwk", JSONObject().put("kty", "EC").put("crv", "P-256").put("x", coordinate(key.w.affineX)).put("y", coordinate(key.w.affineY)))
            .put("hardwareBackedLocalReport", info.isInsideSecureHardware).put("attestation", org.json.JSONArray(store.getCertificateChain(name).map { b64(it.encoded) }))
    }
    fun signature(name: String): Signature = Signature.getInstance("SHA256withECDSA").apply { initSign(store.getKey(alias(name), null) as PrivateKey) }
    fun p1363(der: ByteArray): ByteArray {
        var p = 0; fun read(): Int = der[p++].toInt() and 255
        require(read() == 0x30 && read() == der.size - 2); val out = ByteArray(64)
        for (offset in listOf(0, 32)) { require(read() == 2); var len = read(); require(len in 1..33 && p + len <= der.size && (der[p].toInt() and 128) == 0); if (len == 33) { require(read() == 0); len-- }; System.arraycopy(der, p, out, offset + 32 - len, len); p += len }
        require(p == der.size); return out
    }
    companion object { fun b64(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes) }
}

class MainActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState); window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        val layout = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(24,24,24,24) }
        val input = EditText(this).apply { hint = "JSON: action, alias, challenge/strongBox or tbs"; minLines = 5 }
        val output = TextView(this).apply { setTextIsSelectable(true) }
        val button = Button(this).apply { text = "Run key operation" }
        layout.addView(input); layout.addView(button); layout.addView(output); setContentView(layout)
        button.setOnClickListener { try {
            val request = JSONObject(input.text.toString()); val adapter = AndroidHolderKey(); val alias = request.getString("alias")
            when (request.getString("action")) {
                "generate" -> output.text = adapter.generate(alias, request.getString("challenge").toByteArray(Charsets.UTF_8), request.getBoolean("strongBox")).toString()
                "public" -> output.text = adapter.publicInfo(alias).toString()
                "sign" -> {
                    val tbs = Base64.getUrlDecoder().decode(request.getString("tbs")); require(tbs.size <= 8*1024*1024)
                    val signature = adapter.signature(alias)
                    val prompt = BiometricPrompt.Builder(this).setTitle("Approve credential key operation").setSubtitle("Review the authorized operation in the wallet")
                        .setAllowedAuthenticators(android.hardware.biometrics.BiometricManager.Authenticators.BIOMETRIC_STRONG)
                        .setNegativeButton("Cancel", mainExecutor) { _, _ -> output.text = "OPERATION_CANCELLED" }.build()
                    prompt.authenticate(BiometricPrompt.CryptoObject(signature), CancellationSignal(), mainExecutor, object: BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) { try { val s = result.cryptoObject!!.signature!!; s.update(tbs); output.text = JSONObject().put("signature", AndroidHolderKey.b64(adapter.p1363(s.sign()))).toString() } catch (_: Exception) { output.text = "KEY_OPERATION_FAILED" } }
                        override fun onAuthenticationError(code: Int, message: CharSequence) { output.text = "AUTHENTICATION_FAILED" }
                    })
                }
                else -> error("UNSUPPORTED_OPERATION")
            }
        } catch (_: Exception) { output.text = "KEY_OPERATION_FAILED" } }
    }
}
