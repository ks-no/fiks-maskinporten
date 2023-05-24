package no.ks.fiks.maskinporten.key

import io.kotest.assertions.throwables.shouldThrowExactly
import io.kotest.core.spec.style.StringSpec
import io.kotest.engine.spec.tempfile
import io.kotest.matchers.nulls.beNull
import io.kotest.matchers.shouldNot
import no.ks.fiks.maskinporten.PrivateKeyProperties
import org.bouncycastle.util.io.pem.PemObject
import org.bouncycastle.util.io.pem.PemWriter
import java.security.KeyPairGenerator

class MaskinportenPrivateKeyFactoryTest : StringSpec({

    "Create from pemfile on absolute path" {
        val file = tempfile(suffix = ".pem")

        val keyPair = KeyPairGenerator.getInstance("RSA").genKeyPair()
        PemWriter(file.writer()).use {
            it.writeObject(PemObject("RSA PRIVATE KEY", keyPair.private.encoded))
        }
        MaskinportenPrivateKeyFactory.create(
            PrivateKeyProperties(
                pemFilePath = file.absolutePath
            )
        ) shouldNot beNull()

    }

    "Try to create from non-existing pemfile using absolute path" {
        shouldThrowExactly<IllegalArgumentException> {
            MaskinportenPrivateKeyFactory.create(
                PrivateKeyProperties(
                    pemFilePath = "non-existing.pem"
                )
            )
        }
    }

    "Create from pemfile on classpath" {
        MaskinportenPrivateKeyFactory.create(
            PrivateKeyProperties(
                pemFilePath = "classpath:test-private.pem"
            )
        ) shouldNot beNull()
    }

    "Try to create from non-existing pem file uri" {
        shouldThrowExactly<IllegalArgumentException> {
            MaskinportenPrivateKeyFactory.create(
                PrivateKeyProperties(
                    pemFilePath = "classpath:non-existing.pem"
                )
            )
        }
    }
})



