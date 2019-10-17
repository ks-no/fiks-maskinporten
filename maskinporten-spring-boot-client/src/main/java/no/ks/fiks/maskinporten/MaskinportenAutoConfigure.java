package no.ks.fiks.maskinporten;

import no.ks.fiks.virksomhetsertifikat.VirksomhetSertifikater;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;

@Configuration
@EnableConfigurationProperties({MaskinportenProperties.class})
public class MaskinportenAutoConfigure {

    @Bean
    public Maskinportenklient getMaskinportenklient(MaskinportenProperties properties, VirksomhetSertifikater virksomhetSertifikater) throws UnrecoverableKeyException, CertificateEncodingException, NoSuchAlgorithmException, KeyStoreException {
        VirksomhetSertifikater.KsVirksomhetSertifikatStore authKeyStore = virksomhetSertifikater.requireAuthKeyStore();

        return new Maskinportenklient(authKeyStore.getKeyStore(), authKeyStore.getPrivateKeyAlias(), authKeyStore.getPrivateKeyPassword(), MaskinportenklientProperties.builder()
                .numberOfSecondsLeftBeforeExpire(properties.getNumberOfSecondsLeftBeforeExpire())
                .issuer(properties.getIssuer())
                .audience(properties.getAudience())
                .tokenEndpoint(properties.getTokenEndpoint())
                .build());
    }
}

