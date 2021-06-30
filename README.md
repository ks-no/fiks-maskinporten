# maskinporten-client
![GitHub License](https://img.shields.io/github/license/ks-no/fiks-maskinporten)
[![Maven Central](https://img.shields.io/maven-central/v/no.ks.fiks/fiks-maskinporten)](https://search.maven.org/artifact/no.ks.fiks/fiks-maskinporten)
![GitHub Release Date](https://img.shields.io/github/release-date/ks-no/fiks-maskinporten.svg)
![GitHub Last Commit](https://img.shields.io/github/last-commit/ks-no/fiks-maskinporten.svg)

Dette er en klient som kobler seg opp til Maskinporten (https://difi.github.io/idporten-oidc-dokumentasjon/oidc_auth_server-to-server-oauth2.html) og ber om en JWT-access-token basert på et virksomhetssertifikat, en issuer (konto hos Difi) og ett eller flere scopes.

Husk å be Difi konfigurere opp klienten til å sende JWT-access-token og ikke "token by reference".

Mottatte access-token blir lagret i en cache og vil bli gjenbrukt frem til de utløper. Det er mulig å fjerne access-tokenet fra cachen før det utløper og blir ugyldig. 
Dette er nyttig dersom det gjøres en forespørsel rett før tokenet utløper og det er fare for at tokenet blir ugyldig før forespørselen sendes. 
Konfigurasjon gjøres ved initiering av klienten og styres i feltet "numberOfSecondsLeftBeforeExpire".

## Maven koordinater
```xml
        <dependency>
            <groupId>no.ks.fiks</groupId>
            <artifactId>maskinporten-client</artifactId>
            <version>x.x.x</version>
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

        Maskinportenklient maskinporten = new Maskinportenklient(keyStore, "authentication certificate", keyStorePassword, MaskinportenklientProperties.builder()
                .numberOfSecondsLeftBeforeExpire(10)
                .issuer("<klient-id-utdelt-av-difi>")
                .audience("https://oidc-ver2.difi.no/idporten-oidc-provider/")
                .tokenEndpoint("https://oidc-ver2.difi.no/idporten-oidc-provider/token")
                .build());

        String accessToken = maskinporten.getAccessToken("ks:fiks");
        System.out.println("accessToken = " + accessToken);
    }

    private static KeyStore getKeyStore(String keyStoreFilename, char[] keyStorePassword) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        KeyStore keyStore = KeyStore.getInstance("pkcs12");
        keyStore.load(new FileInputStream(keyStoreFilename), keyStorePassword);
        return keyStore;
    }

}
```
# maskinporten-spring-boot-client
Autokonfigurasjon av maskinporten for Spring Boot.

## Maven koordinater
```xml
        <dependency>
            <groupId>no.ks.fiks</groupId>
            <artifactId>maskinporten-spring-boot-client</artifactId>
            <version>x.x.x</version>
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
I fra versjon 1.0.16 er det også mulig å oppgi _"consumerOrg"_ dersom man skal opptre på [vegne av en annen aktør (delegering)](https://difi.github.io/felleslosninger/maskinporten_func_delegering.html). Settes i så fall til orgnr til aktør man skal opptre på vegne av. Krever også at oppgitt Maskinporten scope er satt opp til å kreve dette.
