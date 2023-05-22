package no.ks.fiks.maskinporten;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.util.UUID;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class MaskinportenklientBuilderTest {

    @DisplayName("An exception should be thrown if private key is not set")
    @Test
    void testPrivateKeyRequired() {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> Maskinportenklient.builder().build());
        assertThat(ex.getMessage()).isEqualTo("The \"privateKey\" property can not be null");
    }

    @DisplayName("An exception should be thrown if key type is not chosen")
    @Test
    void testKeyTypeRequired() {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> Maskinportenklient.builder().withPrivateKey(mock(PrivateKey.class)).build());
        assertThat(ex.getMessage()).isEqualTo("Must configure client to use either virksomhetssertifikat or asymmetric key");
    }

    @DisplayName("An exception should be thrown if properties is not set")
    @Test
    void testPropertiesRequired() {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> Maskinportenklient.builder().withPrivateKey(mock(PrivateKey.class)).usingAsymmetricKey(UUID.randomUUID().toString()).build());
        assertThat(ex.getMessage()).isEqualTo("The \"properties\" property can not be null");
    }

    @DisplayName("Should be able to build client with asymmetric key")
    @Test
    void testValidAymmetricKey() {
        PrivateKey privateKey = mock(PrivateKey.class);
        when(privateKey.getAlgorithm()).thenReturn("RSA");

        assertDoesNotThrow(() -> Maskinportenklient.builder()
                .withPrivateKey(privateKey)
                .usingAsymmetricKey(UUID.randomUUID().toString())
                .withProperties(mock(MaskinportenklientProperties.class))
                .build());
    }

    @DisplayName("Should be able to build client with virksomhetssertifikat")
    @Test
    void testValidVirksomhetssertifikat() {
        PrivateKey privateKey = mock(PrivateKey.class);
        when(privateKey.getAlgorithm()).thenReturn("RSA");

        assertDoesNotThrow(() -> Maskinportenklient.builder()
                .withPrivateKey(privateKey)
                .usingVirksomhetssertifikat(mock())
                .withProperties(mock(MaskinportenklientProperties.class))
                .build());
    }

    @DisplayName("Should be able to build client with custom header provider")
    @Test
    void testValidCustomProvider() {
        PrivateKey privateKey = mock(PrivateKey.class);
        when(privateKey.getAlgorithm()).thenReturn("RSA");

        assertDoesNotThrow(() -> Maskinportenklient.builder()
                .withPrivateKey(privateKey)
                .usingJwsHeaderProvider(mock())
                .withProperties(mock(MaskinportenklientProperties.class))
                .build());
    }

}