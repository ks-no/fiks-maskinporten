package no.ks.fiks.maskinporten

import no.ks.fiks.virksomhetsertifikat.VirksomhetSertifikater
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@Configuration
@EnableConfigurationProperties(MaskinportenProperties::class)
class MaskinportenAutoConfigure {

    @ConditionalOnBean(VirksomhetSertifikater::class)
    @ConditionalOnMissingBean
    @Bean
    fun getMaskinportenklient(properties: MaskinportenProperties, virksomhetSertifikater: VirksomhetSertifikater): Maskinportenklient {
        val authKeyStore = virksomhetSertifikater.requireAuthKeyStore()
        return Maskinportenklient(
            authKeyStore.keyStore, authKeyStore.privateKeyAlias, authKeyStore.privateKeyPassword, properties.toMaskinportenklientProperties())
    }
}