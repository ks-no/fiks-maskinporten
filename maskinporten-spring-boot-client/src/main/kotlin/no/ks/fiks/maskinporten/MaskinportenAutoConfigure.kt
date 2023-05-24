package no.ks.fiks.maskinporten

import no.ks.fiks.maskinporten.key.MaskinportenPrivateKeyFactory
import no.ks.fiks.virksomhetsertifikat.VirksomhetSertifikatAutoConfigure
import no.ks.fiks.virksomhetsertifikat.VirksomhetSertifikater
import org.springframework.boot.autoconfigure.AutoConfiguration
import org.springframework.boot.autoconfigure.AutoConfigureAfter
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean

@AutoConfiguration
@EnableConfigurationProperties(MaskinportenProperties::class)
class MaskinportenAutoConfigure {

    @AutoConfigureAfter(VirksomhetSertifikatAutoConfigure::class)
    @ConditionalOnBean(VirksomhetSertifikater::class)
    inner class MaskinportenUsingVirksomhetSertifikatAutoConfigure {
        @ConditionalOnMissingBean
        @Bean
        fun getMaskinportenklient(properties: MaskinportenProperties, virksomhetSertifikater: VirksomhetSertifikater): Maskinportenklient {
            val authKeyStore = virksomhetSertifikater.requireAuthKeyStore()
            return MaskinportenklientBuilder()
                .withProperties(properties.toMaskinportenklientProperties())
                .usingVirksomhetssertifikat(authKeyStore.certificate)
                .withPrivateKey(authKeyStore.privateKey)
                .build()
        }
    }

    @ConditionalOnMissingBean(VirksomhetSertifikater::class)
    @ConditionalOnProperty("maskinporten.asymmetric-key")
    @EnableConfigurationProperties(PrivateKeyProperties::class)
    inner class MaskinportenUsingAsymetricKeyAutoConfigure {

        @ConditionalOnMissingBean
        @Bean
        fun getMaskinportenklient(properties: MaskinportenProperties, maskinportenPrivateKeyProvider: MaskinportenPrivateKeyProvider): Maskinportenklient {
            return MaskinportenklientBuilder()
                .usingAsymmetricKey(properties.asymmetricKey!!)
                .withPrivateKey(maskinportenPrivateKeyProvider.privateKey)
                .withProperties(properties.toMaskinportenklientProperties())
                .build()
        }

    }

    @ConditionalOnProperty("maskinporten.private-key.pem-file-path")
    @EnableConfigurationProperties(PrivateKeyProperties::class)
    @AutoConfiguration(before = [MaskinportenUsingAsymetricKeyAutoConfigure::class])
    inner class PrivateKeyProviderAutoConfigure {

        @ConditionalOnMissingBean
        @Bean
        fun maskinportenPrivateKeyProvider(properties: PrivateKeyProperties): MaskinportenPrivateKeyProvider {
            return MaskinportenPrivateKeyFactory.create(properties)
        }

    }



}