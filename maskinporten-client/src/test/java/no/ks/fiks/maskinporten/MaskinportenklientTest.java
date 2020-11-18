package no.ks.fiks.maskinporten;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.io.Resources;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.netty.handler.codec.http.HttpMethod;
import no.ks.fiks.maskinporten.error.MaskinportenClientTokenRequestException;
import no.ks.fiks.maskinporten.error.MaskinportenTokenRequestException;
import no.ks.fiks.virksomhetsertifikat.Sertifikat;
import no.ks.fiks.virksomhetsertifikat.SertifikatType;
import no.ks.fiks.virksomhetsertifikat.VirksomhetSertifikater;
import no.ks.fiks.virksomhetsertifikat.VirksomhetSertifikaterProperties;
import org.apache.hc.core5.http.NameValuePair;
import org.apache.hc.core5.net.URLEncodedUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.matchers.Times;
import org.mockserver.mock.action.ExpectationResponseCallback;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;
import org.mockserver.model.HttpStatusCode;
import org.mockserver.model.MediaType;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;
import static org.mockserver.model.HttpClassCallback.callback;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;
import static org.mockserver.model.Parameter.param;
import static org.mockserver.model.ParameterBody.params;

class MaskinportenklientTest {

    private static final String SCOPE = "provider:scope";

    public static final class OidcMockExpectation implements ExpectationResponseCallback {

        private final static ObjectMapper MAPPER = new ObjectMapper().findAndRegisterModules();
        private final KeyPair keyPair;
        private final RSAKey jwkKey;
        private final RSASSASigner signer;

        public OidcMockExpectation() {
            try {
                final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
                keyPairGenerator.initialize(2048);
                keyPair = keyPairGenerator.generateKeyPair();
                jwkKey = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                        .privateKey((RSAPrivateKey) keyPair.getPrivate())
                        .keyID(UUID.randomUUID().toString())
                        .keyUse(KeyUse.SIGNATURE)
                        .build();
                signer = new RSASSASigner(keyPair.getPrivate());
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException("Ukjent algoritme", e);
            }
        }

        @Override
        public HttpResponse handle(HttpRequest httpRequest) throws Exception {
            final List<NameValuePair> formParamPairs = URLEncodedUtils.parse(httpRequest.getBodyAsString(), StandardCharsets.UTF_8);

            final String assertion = formParamPairs.stream().filter(nv -> "assertion".equals(nv.getName())).map(NameValuePair::getValue).findFirst().orElseThrow(() -> new IllegalArgumentException("Fant ikke parameter \"assertion\""));
            final JWTClaimsSet jwtClaimsSet = SignedJWT.parse(assertion).getJWTClaimsSet();
            final String clientId = jwtClaimsSet.getStringArrayClaim("aud")[0];
            final String scope = (String) jwtClaimsSet.getClaim("scope");
            return response()
                    .withStatusCode(HttpStatusCode.OK_200.code())
                    .withContentType(MediaType.APPLICATION_JSON)
                    .withBody(generateToken(clientId, scope), MediaType.APPLICATION_JSON);
        }

        private String generateToken(String clientId, String scope) {
            JWTClaimsSet accessTokenClaimsSet = new JWTClaimsSet.Builder()
                    .claim("consumer", ImmutableMap.of("authority", "iso6523-actorid-upis", "ID", "0192:971032146"))
                    .claim("client_id", clientId)
                    .claim("scope", scope)
                    .build();
            ObjectNode objectNode = MAPPER.createObjectNode();
            objectNode.put("access_token", createJwt(accessTokenClaimsSet));
            objectNode.put("expires_in", 120);
            objectNode.put("scope", scope);
            try {
                return MAPPER.writeValueAsString(objectNode);
            } catch (JsonProcessingException e) {
                throw new IllegalStateException("Kunne ikke skrive JSON", e);
            }
        }

        private String createJwt(JWTClaimsSet claimsSet) {
            final SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .keyID(jwkKey.getKeyID())
                    .build(), new JWTClaimsSet.Builder(claimsSet)
                    .jwtID(UUID.randomUUID().toString())
                    .issueTime(new Date(Clock.systemUTC().millis()))
                    .expirationTime(new Date(Clock.systemUTC().millis() + 120L))
                    .issuer("")
                    .build()
            );
            try {
                signedJWT.sign(signer);
                return signedJWT.serialize();
            } catch (JOSEException e) {
                throw new RuntimeException("Kan ikke signere JWT", e);
            }
        }
    }

    @DisplayName("Generate access token")
    @Test
    void getAccessToken() {
        try (final ClientAndServer client = ClientAndServer.startClientAndServer()) {
            client.when(
                    request()
                            .withSecure(false)
                            .withMethod(HttpMethod.POST.name())
                            .withPath("/token")
                            .withBody(
                                    params(
                                            param("grant_type", Maskinportenklient.GRANT_TYPE)
                                    )
                            )
            ).respond(callback().withCallbackClass(OidcMockExpectation.class));
            final Maskinportenklient maskinportenklient = createClient(String.format("http://localhost:%s/token", client.getLocalPort()));
            final String accessToken = maskinportenklient.getAccessToken(SCOPE);
            assertThat(accessToken).isNotBlank();
        }
    }

    @DisplayName("Generate access token, should be cached the second time")
    @Test
    void getAccessTokenCached() {

        try (final ClientAndServer client = ClientAndServer.startClientAndServer()) {
            client.when(
                    request()
                            .withSecure(false)
                            .withMethod(HttpMethod.POST.name())
                            .withPath("/token")
                            .withBody(
                                    params(
                                            param("grant_type", Maskinportenklient.GRANT_TYPE)
                                    )
                            ),
                    Times.exactly(1)).respond(callback().withCallbackClass(OidcMockExpectation.class));
            final Maskinportenklient maskinportenklient = createClient(String.format("http://localhost:%s/token", client.getLocalPort()));
            final String accessToken = maskinportenklient.getAccessToken(SCOPE);
            assertThat(accessToken).isNotBlank();
            assertThat(maskinportenklient.getAccessToken(SCOPE)).isEqualTo(accessToken);
        }
    }

    @DisplayName("Generate access token fails. The client should not retry")
    @Test
    void getAccessTokenFails() {
        try (final ClientAndServer client = ClientAndServer.startClientAndServer()) {
            client.when(
                    request()
                            .withSecure(false)
                            .withMethod(HttpMethod.POST.name())
                            .withPath("/token")
                            .withBody(
                                    params(
                                            param("grant_type", Maskinportenklient.GRANT_TYPE)
                                    )
                            ),
                    Times.exactly(1))
                    .respond(response()
                            .withBody("FAILURE WAS AN OPTION AFTER ALL")
                            .withStatusCode(HttpStatusCode.INTERNAL_SERVER_ERROR_500.code()));
            final Maskinportenklient maskinportenklient = createClient(String.format("http://localhost:%s/token", client.getLocalPort()));
            final MaskinportenTokenRequestException exception = catchThrowableOfType(() -> maskinportenklient.getAccessToken(SCOPE), MaskinportenTokenRequestException.class);
            assertThat(exception.getStatusCode()).isEqualTo(HttpStatusCode.INTERNAL_SERVER_ERROR_500.code());
        }
    }

    @DisplayName("Try to get generated delegated token, but fails due to missing delegation in Altinn")
    @Test
    void getDelegatedAccessTokenFails403() {
        final String consumerOrg = "888888888";
        final String maskinportenError = String.format("Consumer %s has not delegated access to the scope provider:scope to supplier 999999999. (correlation id: %s)", consumerOrg, UUID.randomUUID());
        try (final ClientAndServer client = ClientAndServer.startClientAndServer()) {
            client.when(
                    request()
                            .withMethod(HttpMethod.POST.name())
                            .withPath("/token")
                            .withBody(
                                    params(
                                            param("grant_type", Maskinportenklient.GRANT_TYPE)
                                    )
                            )
            ).respond(response().withStatusCode(HttpStatusCode.FORBIDDEN_403.code())
                    .withBody(maskinportenError));
            final Maskinportenklient maskinportenklient = createClient(String.format("http://localhost:%s/token", client.getLocalPort()));
            MaskinportenClientTokenRequestException thrown = catchThrowableOfType(() -> maskinportenklient.getDelegatedAccessToken(consumerOrg, SCOPE), MaskinportenClientTokenRequestException.class);
            assertThat(thrown.getMaskinportenError()).isEqualTo(maskinportenError);
            assertThat(thrown.getStatusCode()).isEqualTo(HttpStatusCode.FORBIDDEN_403.code());
        }
    }

    @DisplayName("Generate token with delegation")
    @Test
    void getDelegatedAccessToken() {
        final String consumerOrg = "888888888";
        try (final ClientAndServer client = ClientAndServer.startClientAndServer()) {
            client.when(
                    request()
                            .withSecure(false)
                            .withMethod(HttpMethod.POST.name())
                            .withPath("/token")
                            .withBody(
                                    params(
                                            param("grant_type", Maskinportenklient.GRANT_TYPE)
                                    )
                            )
            ).respond(callback().withCallbackClass(OidcMockExpectation.class));
            final Maskinportenklient maskinportenklient = createClient(String.format("http://localhost:%s/token", client.getLocalPort()));
            final String accessToken = maskinportenklient.getDelegatedAccessToken(consumerOrg, SCOPE);
            assertThat(accessToken).isNotBlank();
        }
    }

    private Maskinportenklient createClient(final String tokenEndpoint) {
        final VirksomhetSertifikater virksomhetSertifikater = createVirksomhetSertifikater();
        VirksomhetSertifikater.KsVirksomhetSertifikatStore authKeyStore = virksomhetSertifikater.requireAuthKeyStore();
        final MaskinportenklientProperties maskinportenklientProperties = new MaskinportenklientProperties("https://ver2.maskinporten.no/",
                tokenEndpoint,
                "77c0a0ba-d20d-424c-b5dd-f1c63da07fc4",
                10,
                null,
                1000);
        try {
            return new Maskinportenklient(authKeyStore.getPrivateKey(), authKeyStore.getCertificate(), maskinportenklientProperties);
        } catch (CertificateEncodingException e) {
            throw new IllegalStateException("Feil under lesing av keystore", e);
        }

    }

    private VirksomhetSertifikater createVirksomhetSertifikater() {
        final VirksomhetSertifikaterProperties properties = new VirksomhetSertifikaterProperties();
        final Sertifikat authSertifikat = new Sertifikat();
        authSertifikat.setCertificateAlias("authentication certificate");
        authSertifikat.setKeystorePassword("KS_PASSWORD");
        authSertifikat.setPrivateKeyAlias("authentication certificate");
        authSertifikat.setPrivateKeyPassword("KS_PASSWORD");
        authSertifikat.setSertifikatType(SertifikatType.AUTH);
        authSertifikat.setKeystorePath(Resources.getResource("KS-virksomhetssertifikat-auth.p12").getPath());
        properties.setSertifikater(ImmutableSet.of(authSertifikat));
        return new VirksomhetSertifikater(properties);
    }

}