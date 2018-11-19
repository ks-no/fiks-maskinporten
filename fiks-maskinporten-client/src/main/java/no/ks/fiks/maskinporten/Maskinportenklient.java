package no.ks.fiks.maskinporten;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
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
import net.minidev.json.JSONObject;

import javax.net.ssl.HttpsURLConnection;
import java.io.*;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.text.ParseException;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static java.util.Collections.singletonList;
import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.concurrent.TimeUnit.MINUTES;

public class Maskinportenklient {
    private static final String GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer";
    private final MaskinportenklientProperties properties;
    private final JWSHeader jwsHeader;
    private final JWSSigner signer;
    private final ExpiringMap<Set<String>, String> map;


    public Maskinportenklient(@NonNull KeyStore keyStore, @NonNull MaskinportenklientProperties properties) throws KeyStoreException, CertificateEncodingException, UnrecoverableKeyException, NoSuchAlgorithmException {
        this.properties = properties;
        jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .x509CertChain(singletonList(Base64.encode(keyStore.getCertificate(properties.getPrivateKeyAlias()).getEncoded())))
                .build();
        signer = new RSASSASigner((PrivateKey) keyStore.getKey(properties.getPrivateKeyAlias(), properties.getPrivateKeyPassword()));

        map = ExpiringMap.builder()
                .variableExpiration()
                .expiringEntryLoader((ExpiringEntryLoader<Set<String>, String>) scopes -> {
                    final JSONObject json = parse(doAquireAccessToken(scopes));
                    final int duration = Integer.parseInt(json.getAsString("expires_in")) - properties.getNumberOfSecondsLeftBeforeExpire();
                    return new ExpiringValue<>(json.getAsString("access_token"), ExpirationPolicy.CREATED, duration, TimeUnit.SECONDS);
                })
                .build();
    }

    public String getAccessToken(Collection<String> scopes) {
        return map.get(new HashSet<>(scopes));
    }

    public String getAccessToken(String... scopes) {
        return getAccessToken(Arrays.asList(String.join(" ", scopes).split("\\s")));
    }

    protected String createJwtRequestForAccessToken(String... scopes) throws JOSEException {
        final long issuedTime = System.currentTimeMillis();
        final SignedJWT signedJWT = new SignedJWT(jwsHeader, new JWTClaimsSet.Builder()
                .audience(properties.getAudience())
                .issuer(properties.getIssuer())
                .claim("scope", String.join(" ", scopes))
                .jwtID(UUID.randomUUID().toString())
                .issueTime(new Date(issuedTime))
                .expirationTime(new Date(issuedTime + MINUTES.convert(2, MILLISECONDS)))
                .build());
        signedJWT.sign(signer);
        return signedJWT.serialize();
    }

    private String doAquireAccessToken(Set<String> scopes) {
        try {
            return aquireAccessToken(scopes);
        } catch (JOSEException | IOException e) {
            throw new RuntimeException(e);
        }
    }

    private String aquireAccessToken(Set<String> scopes) throws JOSEException, IOException {
        final byte[] postData = "grant_type={grant_type}&assertion={assertion}"
                .replace("{grant_type}", GRANT_TYPE)
                .replace("{assertion}", createJwtRequestForAccessToken(scopes.toArray(new String[]{})))
                .getBytes(StandardCharsets.UTF_8);
        final int postDataLength = postData.length;

        final URL tokenEndpoint = new URL(properties.getTokenEndpoint());
        final HttpsURLConnection con = (HttpsURLConnection) tokenEndpoint.openConnection();

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

        if (con.getResponseCode() == 200) {
            return toString(con.getInputStream());
        }

        throw new RuntimeException(String.format("Http response code: %s, url: '%s', scopes: '%s', message: '%s'", con.getResponseCode(), properties.getTokenEndpoint(), scopes, toString(con.getErrorStream())));
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
}
