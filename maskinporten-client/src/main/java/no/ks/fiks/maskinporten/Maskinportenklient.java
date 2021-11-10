package no.ks.fiks.maskinporten;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.NonNull;
import net.jodah.expiringmap.ExpirationPolicy;
import net.jodah.expiringmap.ExpiringEntryLoader;
import net.jodah.expiringmap.ExpiringMap;
import net.jodah.expiringmap.ExpiringValue;
import no.ks.fiks.maskinporten.error.MaskinportenClientTokenRequestException;
import no.ks.fiks.maskinporten.error.MaskinportenTokenRequestException;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.core5.http.*;
import org.apache.hc.core5.http.io.HttpClientResponseHandler;
import org.apache.hc.core5.http.io.support.ClassicRequestBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

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

public class Maskinportenklient {

    private static final Logger log = LoggerFactory.getLogger(Maskinportenklient.class);

    static final String GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer";
    static final String CLAIM_SCOPE = "scope";
    static final String CLAIM_CONSUMER_ORG = "consumer_org";
    static final String CLAIM_RESOURCE = "resource";
    static final String MDC_JTIID = "jtiId";

    private final MaskinportenklientProperties properties;
    private final JWSHeader jwsHeader;
    private final JWSSigner signer;
    private final ExpiringMap<AccessTokenRequest, String> map;

    public Maskinportenklient(@NonNull KeyStore keyStore, String privateKeyAlias, char[] privateKeyPassword, @NonNull MaskinportenklientProperties properties) throws KeyStoreException, CertificateEncodingException, UnrecoverableKeyException, NoSuchAlgorithmException {
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
                    final Map<String, Object> json = parse(doAcquireAccessToken(tokenRequest));
                    final Map<String, Object> accessToken = parseAccessToken(json);
                    final long expiresIn = getExpiresIn(json);
                    final long duration = expiresIn - properties.getNumberOfSecondsLeftBeforeExpire();
                    long exp = TimeUnit.MILLISECONDS.convert(getExp(accessToken), TimeUnit.SECONDS);
                    log.info("Adding access token to cache; access_token.scopes: '{}', access_token.exp: {}, expires_in: {} seconds. Expires from cache in {} seconds ({}).", json.get(CLAIM_SCOPE), new Date(exp), expiresIn, duration, new Date(System.currentTimeMillis() + (1000 * duration)));
                    return new ExpiringValue<>(json.get("access_token").toString(), ExpirationPolicy.CREATED, duration, TimeUnit.SECONDS);
                })
                .build();
    }

    private long getExpiresIn(Map<String, Object> json) {
        Object value = Objects.requireNonNull(json.get("expires_in"), "JSON response fra Maskinporten mangler felt 'expires_in'");
        return Long.parseLong(value.toString());
    }

    private long getExp(Map<String, Object> accessToken) {
        Object value = Objects.requireNonNull(accessToken.get("exp"), "Access token fra Maskinporten mangler felt 'exp'");
        return Long.parseLong(value.toString());
    }

    /**
     * Henter access token med spesifiserte scopes fra Maskinporten.
     *
     * @deprecated Bruk {@link #getAccessToken(AccessTokenRequest)}
     *
     * @param scopes Forespurte scopes for access token
     * @return Access token hentet fra Maskinporten
     */
    @Deprecated
    public String getAccessToken(@NonNull Collection<String> scopes) {
        return getTokenForRequest(AccessTokenRequest.builder().scopes(new HashSet<>(scopes)).build());
    }

    /**
     * Henter access token med spesifiserte scopes fra Maskinporten.
     *
     * @deprecated Bruk {@link #getAccessToken(AccessTokenRequest)}
     *
     * @param scopes Forespurte scopes for access token
     * @return Access token hentet fra Maskinporten
     */
    @Deprecated
    public String getAccessToken(String... scopes) {
        return getAccessToken(scopesToCollection(scopes));
    }

    /**
     * Henter access token med spesifiserte scopes på vegne av en annen organisasjon fra Maskinporten.
     * Bruk av dette krever at organisasjonen har delegert tilgangen i Altinn. Mer informasjon finnes på https://docs.digdir.no/maskinporten_func_delegering.html.
     *
     * @deprecated Bruk {@link #getAccessToken(AccessTokenRequest)}
     *
     * @param consumerOrg Organisasjonsnummer for organisasjon token skal hentes på vegne av
     * @param scopes Forespurte scopes for access token
     * @return Access token hentet fra Maskinporten
     */
    @Deprecated
    public String getDelegatedAccessToken(@NonNull String consumerOrg, @NonNull Collection<String> scopes) {
        return getTokenForRequest(AccessTokenRequest.builder().scopes(new HashSet<>(scopes)).consumerOrg(consumerOrg).build());
    }

    /**
     * Henter access token med spesifiserte scopes på vegne av en annen organisasjon fra Maskinporten.
     * Bruk av dette krever at organisasjonen har delegert tilgangen i Altinn. Mer informasjon finnes på https://docs.digdir.no/maskinporten_func_delegering.html.
     *
     * @deprecated Bruk {@link #getAccessToken(AccessTokenRequest)}
     *
     * @param consumerOrg Organisasjonsnummer for organisasjon token skal hentes på vegne av
     * @param scopes Forespurte scopes for access token
     * @return Access token hentet fra Maskinporten
     */
    @Deprecated
    public String getDelegatedAccessToken(@NonNull String consumerOrg, String... scopes) {
        return getDelegatedAccessToken(consumerOrg, scopesToCollection(scopes));
    }

    /**
     * Henter access token med spesifiserte scopes og audience fra Maskinporten.
     *
     * @deprecated Bruk {@link #getAccessToken(AccessTokenRequest)}
     *
     * @param audience Ønsket audience for access token
     * @param scopes Forespurte scopes for access token
     * @return Access token hentet fra Maskinporten
     */
    @Deprecated
    public String getAccessTokenWithAudience(@NonNull String audience, @NonNull Collection<String> scopes) {
        return getTokenForRequest(AccessTokenRequest.builder().scopes(new HashSet<>(scopes)).audience(audience).build());
    }

    /**
     * Henter access token med spesifiserte scopes og audience fra Maskinporten.
     *
     * @deprecated Bruk {@link #getAccessToken(AccessTokenRequest)}
     *
     * @param audience Ønsket audience for access token
     * @param scopes Forespurte scopes for access token
     * @return Access token hentet fra Maskinporten
     */
    @Deprecated
    public String getAccessTokenWithAudience(@NonNull String audience, String... scopes) {
        return getAccessTokenWithAudience(audience, scopesToCollection(scopes));
    }
    /**
     * Henter access token fra Maskinporten.
     *
     * @param request Request for access token
     * @return Access token hentet fra Maskinporten
     */
    public String getAccessToken(@NonNull AccessTokenRequest request) {
        return getTokenForRequest(request);
    }

    private String getTokenForRequest(@NonNull AccessTokenRequest accessTokenRequest) {
        if (accessTokenRequest.getScopes().isEmpty()) {
            throw new IllegalArgumentException("Minst ett scope må oppgies");
        }
        return map.get(accessTokenRequest);
    }

    protected String createJwtRequestForAccessToken(AccessTokenRequest accessTokenRequest, String jtiId) throws JOSEException {
        final long issuedTimeInMillis = System.currentTimeMillis();
        final long expirationTimeInMillis = issuedTimeInMillis + MILLISECONDS.convert(2, MINUTES);

        final String audience = properties.getAudience();
        final String issuer = properties.getIssuer();
        final String claimScopes = String.join(" ", accessTokenRequest.getScopes());
        final String consumerOrg = Optional.ofNullable(accessTokenRequest.getConsumerOrg()).orElse(properties.getConsumerOrg());
        log.debug("Signing JWTRequest with audience='{}',issuer='{}',scopes='{}',consumerOrg='{}', jtiId='{}'", audience, issuer, claimScopes, consumerOrg, jtiId);
        final JWTClaimsSet.Builder claimBuilder = new JWTClaimsSet.Builder()
                .audience(audience)
                .issuer(issuer)
                .claim(CLAIM_SCOPE, claimScopes)
                .jwtID(jtiId)
                .issueTime(new Date(issuedTimeInMillis))
                .expirationTime(new Date(expirationTimeInMillis));
        Optional.ofNullable(consumerOrg).ifPresent(it -> claimBuilder.claim(CLAIM_CONSUMER_ORG, it));
        Optional.ofNullable(accessTokenRequest.getAudience()).ifPresent(it -> claimBuilder.claim(CLAIM_RESOURCE, it));

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
        final String jtiId = UUID.randomUUID().toString();
        try(MDC.MDCCloseable ignore = MDC.putCloseable(MDC_JTIID, jtiId)) {
            final byte[] postData = "grant_type={grant_type}&assertion={assertion}"
                    .replace("{grant_type}", GRANT_TYPE)
                    .replace("{assertion}", createJwtRequestForAccessToken(accessTokenRequest, jtiId))
                    .getBytes(StandardCharsets.UTF_8);

            final String tokenEndpointUrlString = properties.getTokenEndpoint();
            log.debug("Acquiring access token from \"{}\"", tokenEndpointUrlString);
            long startTime = System.currentTimeMillis();
            try (final CloseableHttpClient httpClient = HttpClientBuilder.create()
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
                            log.warn("Failed to get token: {}", errorFromMaskinporten);
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
    }

    private ClassicHttpRequest createHttpRequest(byte[] entityBuffer) {
        return ClassicRequestBuilder.post(properties.getTokenEndpoint())
                .setCharset(StandardCharsets.UTF_8)
                .addHeader("Charset", StandardCharsets.UTF_8.name())
                .addHeader(HttpHeaders.CONTENT_TYPE, ContentType.APPLICATION_FORM_URLENCODED.getMimeType())
                .setEntity(entityBuffer, ContentType.APPLICATION_FORM_URLENCODED)
                .build();
    }


    private Map<String, Object> parse(String value) {
        try {
            return JSONObjectUtils.parse(value);
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
    }

    private Map<String, Object> parseAccessToken(Map<String, Object> json) {
        try {
            Object accessToken = Objects.requireNonNull(json.get("access_token"), "JSON response fra Maskinporten mangler felt 'access_token'");
            return JWSObject.parse(accessToken.toString())
                    .getPayload()
                    .toJSONObject();
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
    }

    private static Collection<String> scopesToCollection(String... scopes) {
        return Arrays.asList(String.join(" ", scopes).split("\\s"));
    }
}
