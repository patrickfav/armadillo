package at.favre.lib.armadillo.datastore

import android.content.Context
import android.os.Build
import android.util.Log
import androidx.datastore.Serializer
import at.favre.lib.armadillo.*
import at.favre.lib.armadillo.Armadillo.CONTENT_KEY_OUT_BYTE_LENGTH
import at.favre.lib.armadillo.BuildConfig
import java.io.InputStream
import java.io.OutputStream
import java.security.Provider
import java.security.SecureRandom

interface ProtobufProtocol<T> {
  fun toBytes(data: T): ByteArray
  fun fromBytes(bytes: ByteArray): T
  fun fromNothing(): T
}

class ArmadilloSerializer<T>(
    context: Context,
    private val protocol: ProtobufProtocol<T>,
    fingerprintData: List<String> = emptyList(),
    secureRandom: SecureRandom = SecureRandom(),
    additionalDecryptionConfigs: List<EncryptionProtocolConfig> = listOf(),
    enabledKitkatSupport: Boolean = false,
    provider: Provider? = null,
    preferencesSalt: ByteArray = BuildConfig.PREF_SALT
) : Serializer<T> {

  private val password: ByteArrayRuntimeObfuscator?
  private val encryptionProtocol: EncryptionProtocol
  private val fingerprint: EncryptionFingerprint = EncryptionFingerprintFactory.create(
      context,
      buildString { fingerprintData.forEach(::append) }
  )

  init {
    val defaultConfig = EncryptionProtocolConfig.newDefaultConfig()

    val stringMessageDigest = HkdfMessageDigest(
        BuildConfig.PREF_SALT,
        CONTENT_KEY_OUT_BYTE_LENGTH
    )
    val kitKatConfig = takeIf { enabledKitkatSupport }?.run {
      @Suppress("DEPRECATION")
      EncryptionProtocolConfig.newBuilder(defaultConfig.build())
          .authenticatedEncryption(AesCbcEncryption(secureRandom, provider))
          .protocolVersion(Armadillo.KITKAT_PROTOCOL_VERSION)
          .build()
    }
    val config =
        if (kitKatConfig != null && Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) {
          kitKatConfig
        } else {
          EncryptionProtocolConfig
              .newBuilder(defaultConfig.build())
              .authenticatedEncryption(AesGcmEncryption(secureRandom, provider))
              .build()
        }.also { checkKitKatSupport(it.authenticatedEncryption) }

    val factory = DefaultEncryptionProtocol.Factory(
        config,
        fingerprint,
        stringMessageDigest,
        secureRandom,
        false, // enableDerivedPasswordCache,
        if (enabledKitkatSupport) {
          additionalDecryptionConfigs + kitKatConfig
        } else {
          additionalDecryptionConfigs
        },
    )

    encryptionProtocol = factory.create(preferencesSalt)
    password = null // TODO Add password config factory.obfuscatePassword()
  }


  private fun checkKitKatSupport(authenticatedEncryption: AuthenticatedEncryption) {
    if (Build.VERSION.SDK_INT == Build.VERSION_CODES.KITKAT && authenticatedEncryption.javaClass == AesGcmEncryption::class.java) {
      throw UnsupportedOperationException("aes gcm is not supported with KitKat, add support " +
          "manually with Armadillo.Builder.enableKitKatSupport()")
    }
  }

  companion object {
    private const val CRYPTO_KEY = "ArmadilloStore"
  }


  private fun encrypt(content: ByteArray): ByteArray =
      try {
        encryptionProtocol
            .encrypt(
                encryptionProtocol.deriveContentKey(CRYPTO_KEY),
                encryptionProtocol.deobfuscatePassword(password),
                content
            )
      } catch (e: Throwable) {
        throw IllegalStateException(e)
      }


  private fun decrypt(encrypted: ByteArray): ByteArray? {
    if (encrypted.isEmpty()) {
      return null
    }
    try {
      return encryptionProtocol
          .decrypt(
              encryptionProtocol.deriveContentKey(CRYPTO_KEY),
              encryptionProtocol.deobfuscatePassword(password),
              encrypted
          )
    } catch (e: Throwable) {
      Log.e("DataStrore", "decetyp", e)
//      recoveryPolicy.handleBrokenConte(e, keyHash, base64Encrypted, password != null, this)
      // TODO handle this
    }
    return null
  }

  override fun readFrom(input: InputStream): T =
      input
          .readBytes()
          .let(::decrypt)
          .let {
            val bytes = it ?: byteArrayOf()
            if (bytes.isEmpty()) protocol.fromNothing()
            else protocol.fromBytes(bytes)
          }


  override fun writeTo(t: T, output: OutputStream) {
    protocol
        .toBytes(t)
        .let(::encrypt)
        .also(output::write)
  }
}
