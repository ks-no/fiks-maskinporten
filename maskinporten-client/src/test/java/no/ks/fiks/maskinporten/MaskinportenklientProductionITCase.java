package no.ks.fiks.maskinporten;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperties;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThatNoException;

/**
 * Integration test to verify configuration of the Maskinporten client in production.
 */
public class MaskinportenklientProductionITCase {
    private static final Logger logger = LoggerFactory.getLogger(MaskinportenklientProductionITCase.class);
    static final String PROP_KEYSTORE_LOCATION = "keystore_location";
    static final String PROP_KEYSTORE_PASSWORD = "keystore_password";

    static final String PROP_KEYSTORE_PRIVATE_KEY_PASSWORD = "keystore_private_key_password";
    static final String PROP_KEYSTORE_CERTIFICATE_ALIAS = "keystore_certificate_alias";

    static final String PROP_MASKINPORTEN_CLIENT_ID = "maskinporten_client_id";

    static final String PROP_MASKINPORTEN_SCOPE = "maskinporten_scope";

    /**
     * Integration test that requests an access token from Maskinporten using the configured virksomhetssertifikat, clientId and scope.
     * To run you need to specify the following system properties:
     * <ul>
     *     <li><code>keystore_location</code>: location to your keystore</li>
     *     <li><code>keystore_password</code>: password for your keystore</li>
     *     <li><code>keystore_private_key_password</code>: password to unlock your private key from the keystore</li>
     *     <li><code>keystore_certificate_alias</code>: alias for the certificate to be used from your keystore</li>
     *     <li><code>maskinporten_client_id</code>: clientId from Digdir samarbeidsportalen</li>
     *     <li><code>maskinporten_scope</code>: the OIDC scope that you want to request an access token for</li>
     * </ul>
     */
    @EnabledIfSystemProperties(value = {
            @EnabledIfSystemProperty(named = PROP_KEYSTORE_LOCATION, matches = ".*", disabledReason = "Keystore location not set"),
            @EnabledIfSystemProperty(named = PROP_KEYSTORE_PASSWORD, matches = ".*", disabledReason = "Keystore password not set"),
            @EnabledIfSystemProperty(named = PROP_KEYSTORE_CERTIFICATE_ALIAS, matches = ".*", disabledReason = "Keystore certificate alias not set"),
            @EnabledIfSystemProperty(named = PROP_KEYSTORE_PRIVATE_KEY_PASSWORD, matches = ".*", disabledReason = "Keystore private key password not set"),
            @EnabledIfSystemProperty(named = PROP_MASKINPORTEN_CLIENT_ID, matches = ".*", disabledReason = "Maskinporten issuer not set")
    })
    @Test
    void verifyMaskinportenConfigurationProduction() {

        final String maskinportenClientId = System.getProperty(PROP_MASKINPORTEN_CLIENT_ID);
        final String maskinportenScope = System.getProperty(PROP_MASKINPORTEN_SCOPE);
        final Maskinportenklient maskinportenklient = Maskinportenklient.builder()
                .usingVirksomhetssertifikat(loadCertificate())
                .withPrivateKey(loadPrivateKey())
                .withProperties(MaskinportenklientProperties.builder()
                        .issuer(maskinportenClientId)
                        .tokenEndpoint("https://maskinporten.no/token")
                        .audience("https://maskinporten.no/")
                        .build())
                .build();
        logger.info("Requesting access token from Maskinporten with scope {} and clientId {}", maskinportenScope, maskinportenClientId);
        assertThatNoException().isThrownBy(() -> {
                    final String accessToken = maskinportenklient.getAccessToken(AccessTokenRequest.builder()
                            .scope(maskinportenScope)
                            .build());
                    logger.info("Got access token {}", accessToken);
                }
        );
    }

    private PrivateKey loadPrivateKey() {
        final String alias = System.getProperty(PROP_KEYSTORE_CERTIFICATE_ALIAS);
        try {
            return (PrivateKey) loadKeyStore().getKey(alias, System.getProperty(PROP_KEYSTORE_PRIVATE_KEY_PASSWORD).toCharArray());
        } catch (Exception e) {
            throw new IllegalStateException("Unable to load private key with alias " + alias, e);
        }
    }

    private X509Certificate loadCertificate() {
        final String alias = System.getProperty(PROP_KEYSTORE_CERTIFICATE_ALIAS);
        try {
            return (X509Certificate) loadKeyStore().getCertificate(alias);
        } catch (KeyStoreException e) {
            throw new IllegalStateException("Unable to load certificate with alias " + alias, e);
        }
    }

    private KeyStore loadKeyStore() {
        try {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream(System.getProperty(PROP_KEYSTORE_LOCATION)), System.getProperty(PROP_KEYSTORE_PASSWORD).toCharArray());
            return keyStore;
        } catch (Exception e) {
            throw new IllegalStateException("Unable to load keystore", e);
        }
    }
}
