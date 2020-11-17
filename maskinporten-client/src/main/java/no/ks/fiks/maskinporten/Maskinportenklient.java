package no.ks.fiks.maskinporten;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.Builder;
import lombok.Data;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import net.jodah.expiringmap.ExpirationPolicy;
import net.jodah.expiringmap.ExpiringEntryLoader;
import net.jodah.expiringmap.ExpiringMap;
import net.jodah.expiringmap.ExpiringValue;
import net.minidev.json.JSONObject;
import no.ks.fiks.maskinporten.error.MaskinportenClientTokenRequestException;
import no.ks.fiks.maskinporten.error.MaskinportenTokenRequestException;
import org.apache.commons.codec.Charsets;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.core5.http.*;
import org.apache.hc.core5.http.io.HttpClientResponseHandler;
import org.apache.hc.core5.http.io.support.ClassicRequestBuilder;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static java.util.Collections.singletonList;
import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.concurrent.TimeUnit.MINUTES;

@Slf4j
public class Maskinportenklient {
    private static final String GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer";
    static final String CLAIM_SCOPE = "scope";
    static final String CLAIM_CONSUMER_ORG = "consumer_org";
    private final MaskinportenklientProperties properties;
    private final JWSHeader jwsHeader;
    private final JWSSigner signer;
    private final ExpiringMap<AccessTokenRequest, String> map;

    public Maskinportenklient(@NonNull KeyStore keyStore, String privateKeyAlias,  char[] privateKeyPassword, @NonNull MaskinportenklientProperties properties) throws KeyStoreException, CertificateEncodingException, UnrecoverableKeyException, NoSuchAlgorithmException {
        this((PrivateKey) keyStore.getKey(privateKeyAlias, privateKeyPassword), (X509Certificate) keyStore.getCertificate(privateKeyAlias), properties);
    }

    public Maskinportenklient(@NonNull PrivateKey privateKey, X509Certificate certificate, @NonNull MaskinportenklientProperties properties) throws CertificateEncodingException {
        this.properties = properties;
        jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .x509CertChain(singletonList(Base64.encode(certificate.getEncoded())))
                .build();
        signer = new RSASSASigner(privateKey);

        map = ExpiringMap.builder()
                .variableExpiration()
                .expiringEntryLoader((ExpiringEntryLoader<AccessTokenRequest, String>) tokenRequest -> {
                    final JSONObject json = parse(doAcquireAccessToken(tokenRequest));
                    final JSONObject accessToken = parseAccessToken(json);
                    final long expiresIn = (long) json.getAsNumber("expires_in");
                    final long duration = expiresIn - properties.getNumberOfSecondsLeftBeforeExpire();
                    long exp = TimeUnit.MILLISECONDS.convert((long) accessToken.getAsNumber("exp"), TimeUnit.SECONDS);
                    log.info("Adding access token to cache; access_token.scopes: '{}', access_token.exp: {}, expires_in: {} seconds. Expires from cache in {} seconds ({}).", json.getAsString(CLAIM_SCOPE), new Date(exp), expiresIn, duration, new Date(System.currentTimeMillis() + (1000 * duration)));
                    return new ExpiringValue<>(json.getAsString("access_token"), ExpirationPolicy.CREATED, duration, TimeUnit.SECONDS);
                })
                .build();
    }

    public String getAccessToken(@NonNull Collection<String> scopes) {

        return getTokenForRequest(AccessTokenRequest.builder().scopes(new HashSet<>(scopes)).build());
    }

    public String getAccessToken(String... scopes) {
        return getAccessToken(scopesToCollection(scopes));
    }

    public String getDelegatedAccessToken(@NonNull String consumerOrg, @NonNull Collection<String> scopes) {

        return getTokenForRequest(AccessTokenRequest.builder().scopes(new HashSet<>(scopes)).consumerOrg(consumerOrg).build());
    }

    public String getDelegatedAccessToken(@NonNull String consumerOrg, String... scopes) {
        return getDelegatedAccessToken(consumerOrg, scopesToCollection(scopes));
    }

    private String getTokenForRequest(@NonNull AccessTokenRequest accessTokenRequest) {
        if(accessTokenRequest.getScopes().isEmpty()) {
            throw new IllegalArgumentException("Minst ett scope må oppgies");
        }
        return map.get(accessTokenRequest);
    }

    protected String createJwtRequestForAccessToken(AccessTokenRequest accessTokenRequest) throws JOSEException {
        final long issuedTimeInMillis = System.currentTimeMillis();
        final long expirationTimeInMillis = issuedTimeInMillis + MILLISECONDS.convert(2, MINUTES);

        final String audience = properties.getAudience();
        final String issuer = properties.getIssuer();
        final String claimScopes = accessTokenRequest.getScopes().stream().collect(Collectors.joining(" "));
        final String consumerOrg = Optional.ofNullable(accessTokenRequest.consumerOrg).orElse(properties.getConsumerOrg());
        String jtiId = UUID.randomUUID().toString();
        log.debug("Signing JWTRequest with audience='{}',issuer='{}',scopes='{}',consumerOrg='{}', jtiId='{}'", audience, issuer, claimScopes, consumerOrg, jtiId);
        final JWTClaimsSet.Builder claimBuilder = new JWTClaimsSet.Builder()
                .audience(audience)
                .issuer(issuer)
                .claim(CLAIM_SCOPE, claimScopes)
                .jwtID(jtiId)
                .issueTime(new Date(issuedTimeInMillis))
                .expirationTime(new Date(expirationTimeInMillis));

        if(consumerOrg != null) {
            claimBuilder.claim(CLAIM_CONSUMER_ORG, consumerOrg);
        }
        final SignedJWT signedJWT = new SignedJWT(jwsHeader, claimBuilder
                .build());
        signedJWT.sign(signer);
        return signedJWT.serialize();
    }

    private String doAcquireAccessToken(AccessTokenRequest accessTokenRequest) {
        try {
            return acquireAccessToken(accessTokenRequest);
        } catch (JOSEException | IOException e) {
            log.error("Could not acquire access token due to an exception", e);
            throw new RuntimeException(e);
        }
    }

    private String acquireAccessToken(AccessTokenRequest accessTokenRequest) throws JOSEException, IOException {
        final byte[] postData = "grant_type={grant_type}&assertion={assertion}"
                .replace("{grant_type}", GRANT_TYPE)
                .replace("{assertion}", createJwtRequestForAccessToken(accessTokenRequest))
                .getBytes(StandardCharsets.UTF_8);

        final String tokenEndpointUrlString = properties.getTokenEndpoint();
        log.debug("Acquiring access token from \"{}\"", tokenEndpointUrlString);
        long startTime = System.currentTimeMillis();
        try(final CloseableHttpClient httpClient = HttpClientBuilder.create()
                .disableAutomaticRetries()
                .disableRedirectHandling()
                .disableAuthCaching()
                .build()) {
            return httpClient.execute(createHttpRequest(postData), new HttpClientResponseHandler<String>() {
                @Override
                public String handleResponse(final ClassicHttpResponse classicHttpResponse) throws IOException {
                    int responseCode = classicHttpResponse.getCode();
                    log.debug("Access token response received in {} ms with status {}", System.currentTimeMillis() - startTime, responseCode);

                    if (HttpStatus.SC_OK == responseCode) {
                        try (final InputStream contentStream = classicHttpResponse.getEntity().getContent()) {
                            return toString(contentStream);
                        }
                    } else {
                        final String errorFromMaskinporten;
                        try (final InputStream errorContentStream = classicHttpResponse.getEntity().getContent()) {
                            errorFromMaskinporten = toString(errorContentStream);
                        }
                        final String exceptionMessage = String.format("Http response code: %s, url: '%s', scopes: '%s', message: '%s'", responseCode,
                                tokenEndpointUrlString, accessTokenRequest, errorFromMaskinporten);
                        if (responseCode >= HttpStatus.SC_BAD_REQUEST && responseCode < HttpStatus.SC_INTERNAL_SERVER_ERROR) {
                            throw new MaskinportenClientTokenRequestException(exceptionMessage, responseCode, errorFromMaskinporten);
                        } else {
                            throw new MaskinportenTokenRequestException(exceptionMessage, responseCode, errorFromMaskinporten);
                        }
                    }
                }

                private String toString(InputStream inputStream) throws IOException {
                    if (inputStream == null) {
                        return null;
                    }

                    try (InputStreamReader isr = new InputStreamReader(inputStream);
                         BufferedReader br = new BufferedReader(isr)) {
                        return br.lines().collect(Collectors.joining("\n"));
                    }
                }

            });
        }
    }

    private ClassicHttpRequest createHttpRequest(byte[] entityBuffer) {
        return ClassicRequestBuilder.post(properties.getTokenEndpoint())
                .setCharset(Charsets.UTF_8)
                .addHeader("Charset", Charsets.UTF_8.name())
                .addHeader(HttpHeaders.CONTENT_TYPE, ContentType.APPLICATION_FORM_URLENCODED.getMimeType())
                .addHeader(HttpHeaders.CONTENT_LENGTH, Integer.toString(entityBuffer.length))
                .setEntity(entityBuffer, ContentType.APPLICATION_FORM_URLENCODED)
                .build();
    }



    private JSONObject parse(String value) {
        try {
            return JSONObjectUtils.parse(value);
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
    }

    private JSONObject parseAccessToken(JSONObject json) {
        try {
            return JWSObject.parse(json.getAsString("access_token"))
                    .getPayload()
                    .toJSONObject();
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
    }

    private static Collection<String> scopesToCollection(String... scopes) {
        return Arrays.asList(String.join(" ", scopes).split("\\s"));
    }

    @Data
    @Builder
    private static final class AccessTokenRequest {
        @NonNull
        private final Set<String> scopes;
        private final String consumerOrg;
    }
}
