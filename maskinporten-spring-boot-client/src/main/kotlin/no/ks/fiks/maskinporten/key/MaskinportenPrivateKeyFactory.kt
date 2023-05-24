package no.ks.fiks.maskinporten.key

import no.ks.fiks.maskinporten.MaskinportenPrivateKeyProvider
import no.ks.fiks.maskinporten.PrivateKeyProperties
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.util.io.pem.PemReader
import org.springframework.util.ResourceUtils
import java.io.File
import java.io.FileNotFoundException
import java.io.FileReader
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.interfaces.RSAPrivateKey
import java.security.spec.PKCS8EncodedKeySpec

object MaskinportenPrivateKeyFactory {

    fun create(privateKeyProperties: PrivateKeyProperties): MaskinportenPrivateKeyProvider {
        return MaskinportenPrivateKeyProvider(
            privateKey = getPrivateKey(privateKeyProperties.pemFilePath))
    }

    private fun getPrivateKey(pemFilePath: String): PrivateKey = try {
        val file = resolveFile(pemFilePath)
        val keyFactory = KeyFactory.getInstance("RSA", BouncyCastleProvider())
        FileReader(file).use { fileReader ->
            PemReader(fileReader).use { pemReader ->
                val pemObject = pemReader.readPemObject()
                keyFactory.generatePrivate(PKCS8EncodedKeySpec(pemObject.content)) as RSAPrivateKey
            }
        }
    } catch (e: FileNotFoundException) {
        throw IllegalArgumentException("Could not resolve file for path url $pemFilePath", e)
    }


    private fun resolveFile(path: String): File {
        return if (ResourceUtils.isUrl(path)) {
            try {
                ResourceUtils.getFile(path)
            } catch (e: FileNotFoundException) {
                throw IllegalArgumentException("Could not resolve file for path url $path", e)
            }
        } else {
            File(path).takeIf { it.exists() } ?: throw IllegalArgumentException("Could not resolve file for path $path")
        }
    }
}