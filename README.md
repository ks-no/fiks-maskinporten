# maskinporten-client
![GitHub License](https://img.shields.io/github/license/ks-no/fiks-maskinporten)
[![Maven Central](https://img.shields.io/maven-central/v/no.ks.fiks/maskinporten)](https://search.maven.org/artifact/no.ks.fiks/maskinporten)
![GitHub Release Date](https://img.shields.io/github/release-date/ks-no/fiks-maskinporten.svg)
![GitHub Last Commit](https://img.shields.io/github/last-commit/ks-no/fiks-maskinporten.svg)

Dette er en klient som kobler seg opp til Maskinporten (https://difi.github.io/idporten-oidc-dokumentasjon/oidc_auth_server-to-server-oauth2.html) og ber om en JWT-access-token basert på et virksomhetssertifikat, en issuer (konto hos Difi) og ett eller flere scopes.

Husk å be Difi konfigurere opp klienten til å sende JWT-access-token og ikke "token by reference".

Mottatte access-token blir lagret i en cache og vil bli gjenbrukt frem til de utløper. Det er mulig å fjerne access-tokenet fra cachen før det utløper og blir ugyldig. 
Dette er nyttig dersom det gjøres en forespørsel rett før tokenet utløper og det er fare for at tokenet blir ugyldig før forespørselen sendes. 
Konfigurasjon gjøres ved initiering av klienten og styres i feltet "numberOfSecondsLeftBeforeExpire".

## Maskinporten-miljøer
Digdir vedlikeholder [liste med gyldige verdier for miljøene de tilbyr](https://docs.digdir.no/maskinporten_func_wellknown.html)

## Versjoner

| Versjon | Java baseline | Spring Boot versjon | Status      | 
|---------|---------------|---------------------|-------------|
| 3.x     | Java 17       | 3.X                 | Aktiv       | 
| 2.X     | Java 11       | 2.X                 | Vedlikehold |

### Status
- **Aktiv**: versjon som aktivt utvikles og holdes oppdatert mht. avhengigheter
- **Vedlikehold**: kun kritiske feil vil bli adressert


## Maven koordinater
```xml
        <dependency>
            <groupId>no.ks.fiks</groupId>
            <artifactId>maskinporten-client</artifactId>
            <version>x.x.x</version>
        </dependency>
```

## Eksempel
### Java
```java
import no.ks.fiks.maskinporten.Maskinportenklient;
import no.ks.fiks.maskinporten.MaskinportenklientProperties;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class Application {

    public static void main(String[] args) throws Exception {
        String keyStoreFilename = "virksomhetssertifikat-auth.p12";
        String alias = "authentication certificate";
        char[] keyStorePassword = "passord".toCharArray();
        KeyStore keyStore = getKeyStore(keyStoreFilename, keyStorePassword);

        Maskinportenklient maskinporten = Maskinportenklient.builder()
                .withPrivateKey((PrivateKey) keyStore.getKey(alias, keyStorePassword))
                .withProperties(
                        MaskinportenklientProperties.builder()
                                .numberOfSecondsLeftBeforeExpire(10)
                                .issuer("<klient-id-utdelt-av-difi>")
                                .audience("https://ver2.maskinporten.no/")
                                .tokenEndpoint("https://ver2.maskinporten.no/token")
                                .build()
                )
                .usingVirksomhetssertifikat((X509Certificate) keyStore.getCertificate(alias))
                .build();

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

### Kotlin
```kotlin
val keyStore: Keystore = ...
val alias = "mykey"
val password = "keypassword"
val maskinportenklientProperties = MaskinportenklientProperties(
            audience = "https://ver2.maskinporten.no/",
            tokenEndpoint = "https://ver2.maskinporten.no/token",
            issuer = "<klient-id-utdelt-av-difi>",
            numberOfSecondsLeftBeforeExpire = 10)
val klient = Maskinportenklient(keyStore, "mykey", "keypassword".toCharArray(), maskinportenklientProperties)
val klient = Maskinportenklient.builder()
    .withPrivateKey(keyStore.getKey(alias, keyStorePassword) as PrivateKey)
    .withProperties(maskinportenklientProperties)
    .usingVirksomhetssertifikat(keyStore.getCertificate(alias) as X509Certificate)
    .build()
```
### Bruk egen CloseableHttpClient
Klienten er basert på Apache HttpClient 5.1.x. Dersom du vil kan du konfigurere denne selv. Da må du selv sørge for å lukke den når klienten ikke skal brukes mer
```java
CloseableHttpClient httpClient = ... // 
Maskinportenklient maskinporten = Maskinportenklient.builder()
    .withPrivateKey((PrivateKey) keyStore.getKey(alias, keyStorePassword))
    .withProperties(
        MaskinportenklientProperties.builder()
            .audience("https://ver2.maskinporten.no/")
            .tokenEndpoint(tokenEndpoint)
            .issuer("77c0a0ba-d20d-424c-b5dd-f1c63da07fc4")
            .numberOfSecondsLeftBeforeExpire(10)
            .providedHttpClient(httpClient)
            .build()
    )
    .usingVirksomhetssertifikat((X509Certificate) keyStore.getCertificate(alias))
    .build();
```

### Bruk av asymmetriske nøkler
Maskinporten har støtte for bruk av asymmetriske nøkler i stedet for virksomhetssertifikat, som beskrevet [her](https://docs.digdir.no/docs/Maskinporten/maskinporten_guide_apikonsument#registrere-klient-som-bruker-egen-n%C3%B8kkel).

Klient-builderen har støtte for at en slik nøkkel kan konfigureres slik:
```java
Maskinportenklient.builder()
        .withPrivateKey(...)
        .withProperties(...)
        .usingAsymmetricKey("<asymmetrisk nøkkel>")
        .build();
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
### Med virksomhetssertifikat
```yaml
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
### Med bruk av asymetrisk nøkkel
```yaml
maskinporten:
  audience: <AUDIENCE>
  tokenEndpoint: <TOKEN_ENDPOINT>
  issuer: <ISSUER>
  numberOfSecondsLeftBeforeExpire: <NUMBER_OF_SECOUNDS>
  asymmetricKey: <ASYMMETRIC_KEY_ID>
  privateKey:
    pemFilePath: <URI OR FILE PATH>
```   


I fra versjon 1.0.16 er det også mulig å oppgi _"consumerOrg"_ dersom man skal opptre på [vegne av en annen aktør (delegering)](https://difi.github.io/felleslosninger/maskinporten_func_delegering.html). Settes i så fall til orgnr til aktør man skal opptre på vegne av. Krever også at oppgitt Maskinporten scope er satt opp til å kreve dette.
