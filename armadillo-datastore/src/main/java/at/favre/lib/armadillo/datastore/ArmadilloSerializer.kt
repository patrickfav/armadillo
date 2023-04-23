package at.favre.lib.armadillo.datastore

import android.content.Context
import android.os.Build
import androidx.datastore.core.Serializer
import at.favre.lib.armadillo.*
import at.favre.lib.armadillo.Armadillo.CONTENT_KEY_OUT_BYTE_LENGTH
import at.favre.lib.armadillo.BuildConfig
import java.io.InputStream
import java.io.OutputStream
import java.security.Provider
import java.security.SecureRandom

class ArmadilloSerializer<T>(
        context: Context,
        private val protocol: ProtobufProtocol<T>,
        password: CharArray? = null,
        fingerprintData: List<String> = emptyList(),
        secureRandom: SecureRandom = SecureRandom(),
        additionalDecryptionConfigs: List<EncryptionProtocolConfig> = listOf(),
        enabledKitkatSupport: Boolean = false,
        provider: Provider? = null,
        preferencesSalt: ByteArray = BuildConfig.PREF_SALT
) : Serializer<T> {

    private val serializerPassword: ByteArrayRuntimeObfuscator?
    private val encryptionProtocol: EncryptionProtocol
    private val fingerprint: EncryptionFingerprint = EncryptionFingerprintFactory.create(
            context,
            buildString { fingerprintData.forEach(::append) }
    )
    private val defaultConfig = EncryptionProtocolConfig.newDefaultConfig()
    private val kitKatConfig by lazy {
        @Suppress("DEPRECATION")
        EncryptionProtocolConfig.newBuilder(defaultConfig.build())
                .authenticatedEncryption(AesCbcEncryption(secureRandom, provider))
                .protocolVersion(Armadillo.KITKAT_PROTOCOL_VERSION)
                .build()
    }

    init {

        val stringMessageDigest = HkdfMessageDigest(
                BuildConfig.PREF_SALT,
                CONTENT_KEY_OUT_BYTE_LENGTH
        )

        val config =
                if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) {
                    kitKatConfig
                } else {
                    EncryptionProtocolConfig
                            .newBuilder(defaultConfig.build())
                            .authenticatedEncryption(AesGcmEncryption(secureRandom, provider))
                            .build()
                }
        checkKitKatSupport(config.authenticatedEncryption)

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
        serializerPassword = password?.let(factory::obfuscatePassword)
    }


    private fun checkKitKatSupport(authenticatedEncryption: AuthenticatedEncryption) {
        if (Build.VERSION.SDK_INT == Build.VERSION_CODES.KITKAT && authenticatedEncryption.javaClass == AesGcmEncryption::class.java) {
            throw UnsupportedOperationException("aes gcm is not supported with KitKat, add support " +
                    "manually with Armadillo.Builder.enableKitKatSupport()")
        }
    }

    companion object {
        private const val CRYPTO_KEY = "ArmadilloStoreSerializer"
    }


    private fun encrypt(content: ByteArray): ByteArray = with(encryptionProtocol) {
        encrypt(
                deriveContentKey(CRYPTO_KEY),
                deobfuscatePassword(serializerPassword),
                content
        )
    }


    private fun decrypt(encrypted: ByteArray): ByteArray? =
            if (encrypted.isEmpty()) {
                null
            } else {
                encryptionProtocol
                        .decrypt(
                                encryptionProtocol.deriveContentKey(CRYPTO_KEY),
                                encryptionProtocol.deobfuscatePassword(serializerPassword),
                                encrypted
                        )
            }

    override fun readFrom(input: InputStream): T =
        input
                .readBytes()
                .let(::decrypt)
                .let {
                    val bytes = it ?: byteArrayOf()
                    if (bytes.isEmpty()) defaultValue
                    else protocol.decode(bytes)
                }


    override fun writeTo(t: T, output: OutputStream) {
        protocol
                .encode(t)
                .let(::encrypt)
                .also(output::write)
    }

    override val defaultValue: T
        get() = protocol.default()
}
