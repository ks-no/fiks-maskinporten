package no.ks.fiks.maskinporten

import io.micrometer.core.instrument.MeterRegistry
import io.micrometer.observation.ObservationRegistry
import no.ks.fiks.maskinporten.key.MaskinportenPrivateKeyFactory
import no.ks.fiks.maskinporten.observability.DefaultMaskinportenKlientObservability
import no.ks.fiks.maskinporten.observability.MaskinportenKlientObservability
import no.ks.fiks.maskinporten.observability.MicrometerMaskinportenKlientObservability
import no.ks.fiks.virksomhetsertifikat.VirksomhetSertifikatAutoConfigure
import no.ks.fiks.virksomhetsertifikat.VirksomhetSertifikater
import org.springframework.boot.autoconfigure.AutoConfiguration
import org.springframework.boot.autoconfigure.AutoConfigureAfter
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Condition
import org.springframework.context.annotation.ConditionContext
import org.springframework.context.annotation.Conditional
import org.springframework.core.env.get
import org.springframework.core.type.AnnotatedTypeMetadata

@AutoConfiguration
@EnableConfigurationProperties(MaskinportenProperties::class)
class MaskinportenAutoConfigure {

    /**
     * Configures observability for MaskinportenKlient
     */
    @AutoConfiguration
    inner class Observability {
        @Bean
        @ConditionalOnBean(MeterRegistry::class, ObservationRegistry::class)
        @ConditionalOnMissingBean
        fun micrometerMaskinportenKlientObservability(observationRegistry: ObservationRegistry, metricRegistry: MeterRegistry): MaskinportenKlientObservability {
            return MicrometerMaskinportenKlientObservability(observationRegistry, metricRegistry)
        }

        @Bean
        @ConditionalOnBean(MeterRegistry::class)
        @ConditionalOnMissingBean
        fun micrometerMaskinportenKlientObservabilityWithoutTracing(metricRegistry: MeterRegistry): MaskinportenKlientObservability {
            return MicrometerMaskinportenKlientObservability(null, metricRegistry)
        }

        @Bean
        @ConditionalOnMissingBean(MaskinportenKlientObservability::class)
        fun defaultMaskinportenKlientObservability(): MaskinportenKlientObservability = DefaultMaskinportenKlientObservability()
    }

    @AutoConfigureAfter(VirksomhetSertifikatAutoConfigure::class)
    @ConditionalOnClass(VirksomhetSertifikater::class)
    inner class MaskinportenUsingVirksomhetSertifikatAutoConfigure {

        @ConditionalOnMissingBean
        @Conditional(MissingAsymmetricKeyConfigurationCondition::class)
        @Bean
        fun getMaskinportenklient(properties: MaskinportenProperties,
                                  virksomhetSertifikater: VirksomhetSertifikater,
                                  maskinportenKlientObservability: MaskinportenKlientObservability): Maskinportenklient {
            val authKeyStore = virksomhetSertifikater.requireAuthKeyStore()
            return MaskinportenklientBuilder()
                .withProperties(properties.toMaskinportenklientProperties())
                .usingVirksomhetssertifikat(authKeyStore.certificate)
                .withPrivateKey(authKeyStore.privateKey)
                .havingObservabilitySupport(maskinportenKlientObservability)
                .build()
        }
    }

    @ConditionalOnProperty("maskinporten.asymmetric-key")
    @EnableConfigurationProperties(PrivateKeyProperties::class)
    inner class MaskinportenUsingAsymetricKeyAutoConfigure {

        @ConditionalOnMissingBean
        @Bean
        fun getMaskinportenklient(
            properties: MaskinportenProperties,
            maskinportenPrivateKeyProvider: MaskinportenPrivateKeyProvider,
            maskinportenKlientObservability: MaskinportenKlientObservability
        ): Maskinportenklient {
            return MaskinportenklientBuilder()
                .usingAsymmetricKey(properties.asymmetricKey!!)
                .withPrivateKey(maskinportenPrivateKeyProvider.privateKey)
                .withProperties(properties.toMaskinportenklientProperties())
                .havingObservabilitySupport(maskinportenKlientObservability)
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

class MissingAsymmetricKeyConfigurationCondition: Condition {
    override fun matches(context: ConditionContext, metadata: AnnotatedTypeMetadata): Boolean = context.environment["maskinporten.asymmetric-key"]
        .isNullOrEmpty()

}