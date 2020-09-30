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

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
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
        log.debug("Signing JWTRequest with audience='{}',issuer='{}',scopes='{}',consumerOrg='{}'", audience, issuer, claimScopes, consumerOrg);
        final JWTClaimsSet.Builder claimBuilder = new JWTClaimsSet.Builder()
                .audience(audience)
                .issuer(issuer)
                .claim(CLAIM_SCOPE, claimScopes)
                .jwtID(UUID.randomUUID().toString())
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
        final int postDataLength = postData.length;

        final String tokenEndpointUrlString = properties.getTokenEndpoint();
        log.debug("Acquiring access token from \"{}\"", tokenEndpointUrlString);
        long startTime = System.currentTimeMillis();
        final URL tokenEndpoint = new URL(tokenEndpointUrlString);
        final HttpURLConnection con = (HttpURLConnection) tokenEndpoint.openConnection();
        con.setConnectTimeout(properties.getTimeoutMillis());
        con.setReadTimeout(properties.getTimeoutMillis());
        con.setDoOutput(true);
        con.setInstanceFollowRedirects(false);
        con.setRequestMethod("POST");
        con.setRequestProperty("Charset", "utf-8");
        con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        con.setRequestProperty("Content-Length", Integer.toString(postDataLength));
        con.setUseCaches(false);

        try (final DataOutputStream dos = new DataOutputStream(con.getOutputStream())) {
            dos.write(postData);
        }

        int responseCode = con.getResponseCode();
        log.debug("Access token response received in {} ms with status {}", System.currentTimeMillis() - startTime, responseCode);
        if (responseCode == 200) {
            return toString(con.getInputStream());
        }

        throw new RuntimeException(String.format("Http response code: %s, url: '%s', scopes: '%s', message: '%s'", con.getResponseCode(),
                                                 tokenEndpointUrlString, accessTokenRequest, toString(con.getErrorStream())));
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
