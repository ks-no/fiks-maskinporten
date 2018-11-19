# fiks-maskinporten-client
Dette er en klient som kobler seg opp til Maskinporten (https://difi.github.io/idporten-oidc-dokumentasjon/oidc_auth_server-to-server-oauth2.html) og ber om en JWT-access-token basert på et virksomhetssertifikat, en issuer (konto hos Difi) og ett eller flere scopes.

Husk å be Difi konfigurere opp klienten til å sende JWT-access-token og ikke "token by reference".

Mottatte access-token blir lagret i en cache og vil bli gjenbrukt frem til de utløper. Det er mulig å fjerne access-tokenet fra cachen før det utløper og blir ugyldig. 
Dette er nyttig dersom det gjøres en forespørsel rett før tokenet utløper og det er fare for at tokenet blir ugyldig før forespørselen sendes. 
Konfigurasjon gjøres ved initiering av klienten og styres i feltet "numberOfSecondsLeftBeforeExpire".

## Maven koordinater
```xml
        <dependency>
            <groupId>no.ks.fiks</groupId>
            <artifactId>fiks-maskinporten-client</artifactId>
            <version>1.0.2</version>
        </dependency>
```

## Eksempel
```java
import no.ks.fiks.maskinporten.Maskinportenklient;
import no.ks.fiks.maskinporten.MaskinportenklientProperties;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public class Application {

    public static void main(String[] args) throws Exception {
        String keyStoreFilename = "virksomhetssertifikat-auth.p12";
        char[] keyStorePassword = "passord".toCharArray();
        KeyStore keyStore = getKeyStore(keyStoreFilename, keyStorePassword);

        Maskinportenklient maskinporten = new Maskinportenklient(keyStore, MaskinportenklientProperties.builder()
                .privateKeyPassword(keyStorePassword)
                .privateKeyAlias("authentication certificate")
                .numberOfSecondsLeftBeforeExpire(10)
                .issuer("<klient-id-utdelt-av-difi>")
                .audience("https://oidc-ver2.difi.no/idporten-oidc-provider/")
                .tokenEndpoint("https://oidc-ver2.difi.no/idporten-oidc-provider/token")
                .build());

        String accessToken = maskinporten.getAccessToken("ks");
        System.out.println("accessToken = " + accessToken);
    }

    private static KeyStore getKeyStore(String keyStoreFilename, char[] keyStorePassword) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        KeyStore keyStore = KeyStore.getInstance("pkcs12");
        keyStore.load(new FileInputStream(keyStoreFilename), keyStorePassword);
        return keyStore;
    }

}
```
# fiks-maskinporten-spring-boot-client
Autokonfigurasjon av maskinporten for Spring Boot.

## Maven koordinater
```xml
        <dependency>
            <groupId>no.ks.fiks</groupId>
            <artifactId>fiks-maskinporten-spring-boot-client</artifactId>
            <version>1.0.2</version>
        </dependency>
```
## Eksempel
```java
    @Bean
    public KontaktOgReservasjonsregisteretApi getKontaktOgReservasjonsregisteretApi(Maskinportenklient maskinportenklient) {
        return new KontaktOgReservasjonsregisteretApi(maskinportenklient);
    }
```

## Konfigurasjon - application.yaml
```json
virksomhetsertifikat.sertifikater:
- sertifikat-type: AUTH
  keystore-password: <KEYSTORE_PASSWORD>
  keystore-path: <KEYSTORE_PATH>
  certificate-alias: <CERTIFICATE_ALIAS>
  private-key-alias: <PRIVATE_KEY_ALIAS>
  private-key-password: <PRIVATE_KEY_PASSWORD>

maskinporten:
  audience: <AUDIENCE>
  tokenEndpoint: <TOKEN_ENDPOINT>
  issuer: <ISSUER>
  numberOfSecondsLeftBeforeExpire: <NUMBER_OF_SECOUNDS>
```

