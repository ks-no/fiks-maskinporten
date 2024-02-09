package no.ks.fiks.maskinporten;

import com.codahale.metrics.MetricRegistry;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.common.collect.ImmutableMap;
import com.google.common.io.Resources;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.micrometer.core.instrument.observation.DefaultMeterObservationHandler;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import io.micrometer.observation.ObservationRegistry;
import io.netty.handler.codec.http.HttpMethod;
import no.ks.fiks.maskinporten.error.MaskinportenClientTokenRequestException;
import no.ks.fiks.maskinporten.error.MaskinportenTokenRequestException;
import no.ks.fiks.maskinporten.error.MaskinportenTokenTemporarilyUnavailableException;
import no.ks.fiks.maskinporten.observability.DropwizardMetricsMaskinportenKlientObservability;
import no.ks.fiks.maskinporten.observability.MaskinportenKlientObservability;
import no.ks.fiks.maskinporten.observability.MicrometerMaskinportenKlientObservability;
import no.ks.fiks.virksomhetsertifikat.Sertifikat;
import no.ks.fiks.virksomhetsertifikat.SertifikatType;
import no.ks.fiks.virksomhetsertifikat.VirksomhetSertifikater;
import org.apache.hc.client5.http.HttpHostConnectException;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.core5.http.NameValuePair;
import org.apache.hc.core5.net.WWWFormCodec;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.matchers.Times;
import org.mockserver.mock.action.ExpectationResponseCallback;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;
import org.mockserver.model.HttpStatusCode;
import org.mockserver.model.MediaType;

import java.io.IOException;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Clock;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;

import static org.assertj.core.api.Assertions.*;
import static org.mockserver.model.HttpClassCallback.callback;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;
import static org.mockserver.model.Parameter.param;
import static org.mockserver.model.ParameterBody.params;

@SuppressWarnings("deprecation")
class MaskinportenklientTest {

    private static final String SCOPE = "provider:scope";

    private static final String JWT_BEARER_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer";

    public static final class OidcMockExpectation implements ExpectationResponseCallback {

        private final static ObjectMapper MAPPER = new ObjectMapper().findAndRegisterModules();
        private final RSAKey jwkKey;
        private final RSASSASigner signer;

        static String previousJwt = null;

        public OidcMockExpectation() {
            try {
                final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
                keyPairGenerator.initialize(2048);
                KeyPair keyPair = keyPairGenerator.generateKeyPair();
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
            final List<NameValuePair> formParamPairs = WWWFormCodec.parse(httpRequest.getBodyAsString(), StandardCharsets.UTF_8);

            final String assertion = formParamPairs.stream().filter(nv -> "assertion".equals(nv.getName())).map(NameValuePair::getValue).findFirst().orElseThrow(() -> new IllegalArgumentException("Fant ikke parameter \"assertion\""));
            final JWTClaimsSet jwtClaimsSet = SignedJWT.parse(assertion).getJWTClaimsSet();
            final String clientId = jwtClaimsSet.getStringArrayClaim("aud")[0];
            final String scope = jwtClaimsSet.getStringClaim("scope");
            final String resource = jwtClaimsSet.getStringClaim("resource");
            final String pid = jwtClaimsSet.getStringClaim("pid");
            return response()
                    .withStatusCode(HttpStatusCode.OK_200.code())
                    .withContentType(MediaType.APPLICATION_JSON)
                    .withBody(generateToken(clientId, scope, resource, pid), MediaType.APPLICATION_JSON);
        }

        private String generateToken(String clientId, String scope, String resource, String pid) {
            JWTClaimsSet.Builder claimsSetBuilder = new JWTClaimsSet.Builder()
                    .claim("consumer", ImmutableMap.of("authority", "iso6523-actorid-upis", "ID", "0192:971032146"))
                    .claim("client_id", clientId)
                    .claim("scope", scope);
            Optional.ofNullable(resource).ifPresent(it -> claimsSetBuilder.claim("aud", resource));
            Optional.ofNullable(pid).ifPresent(it -> claimsSetBuilder.claim("pid", pid));
            ObjectNode objectNode = MAPPER.createObjectNode();
            String jwt = createJwt(claimsSetBuilder.build());
            objectNode.put("access_token", jwt);
            objectNode.put("expires_in", 120);
            objectNode.put("scope", scope);
            try {
                previousJwt = jwt;
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
                                            param("grant_type", JWT_BEARER_GRANT)
                                    )
                            )
            ).respond(callback().withCallbackClass(OidcMockExpectation.class));
            Maskinportenklient maskinportenklient = createClient(String.format("http://localhost:%s/token", client.getLocalPort()));
            assertThat(maskinportenklient.getAccessToken(SCOPE)).isEqualTo(OidcMockExpectation.previousJwt);

        }
    }

    @DisplayName("Generate access token while observing with micrometer")
    @Test
    void getAccessTokenWithMicrometerObservability() {
        final var meterRegistry = new SimpleMeterRegistry();
        final ObservationRegistry observationRegistry = ObservationRegistry.create();
        observationRegistry.observationConfig()
                .observationHandler(new DefaultMeterObservationHandler(meterRegistry));
        final var maskinportenKlientObservability = new MicrometerMaskinportenKlientObservability(observationRegistry, meterRegistry);
        try (final ClientAndServer client = ClientAndServer.startClientAndServer()) {
            client.when(
                    request()
                            .withSecure(false)
                            .withMethod(HttpMethod.POST.name())
                            .withPath("/token")
                            .withBody(
                                    params(
                                            param("grant_type", JWT_BEARER_GRANT)
                                    )
                            )
            ).respond(callback().withCallbackClass(OidcMockExpectation.class));
            Maskinportenklient maskinportenklient = createClientWithObservability(String.format("http://localhost:%s/token", client.getLocalPort()), maskinportenKlientObservability);
            assertThat(maskinportenklient.getAccessToken(SCOPE)).isEqualTo(OidcMockExpectation.previousJwt);
        }
        assertThat(meterRegistry).satisfies(reg ->
                assertThat(reg.get("httpcomponents.httpclient.request").timer().count()).isEqualTo(1)
        );
        assertThat(meterRegistry).satisfies(reg ->
                assertThat(reg.get("httpcomponents.httpclient.request.active").longTaskTimer())).isNotNull();
        meterRegistry.close();
    }

    @DisplayName("Generate access token while observing with dropwizard metrics")
    @Test
    void getAccessTokenWithDropwizardMetricObservability() {
        final var metricRegistry = new MetricRegistry();
        final var maskinportenKlientObservability = new DropwizardMetricsMaskinportenKlientObservability(metricRegistry);
        try (final ClientAndServer client = ClientAndServer.startClientAndServer()) {
            client.when(
                    request()
                            .withSecure(false)
                            .withMethod(HttpMethod.POST.name())
                            .withPath("/token")
                            .withBody(
                                    params(
                                            param("grant_type", JWT_BEARER_GRANT)
                                    )
                            )
            ).respond(callback().withCallbackClass(OidcMockExpectation.class));
            Maskinportenklient maskinportenklient = createClientWithObservability(String.format("http://localhost:%s/token", client.getLocalPort()), maskinportenKlientObservability);
            assertThat(maskinportenklient.getAccessToken(SCOPE)).isEqualTo(OidcMockExpectation.previousJwt);

        }
        assertThat(metricRegistry).satisfies(reg ->
                assertThat(reg.getTimers().firstKey()).isEqualTo("org.apache.hc.client5.http.classic.HttpClient.post-requests")
        );
    }

    @DisplayName("Generate access token, but using provided http client")
    @Test
    void getAccessTokenUsingProvidedHttpClient() {
        try (final ClientAndServer client = ClientAndServer.startClientAndServer()) {
            client.when(
                    request()
                            .withSecure(false)
                            .withMethod(HttpMethod.POST.name())
                            .withPath("/token")
                            .withBody(
                                    params(
                                            param("grant_type", JWT_BEARER_GRANT)
                                    )
                            )
            ).respond(callback().withCallbackClass(OidcMockExpectation.class));

            try (CloseableHttpClient httpClient = HttpClientBuilder.create().disableAutomaticRetries().disableRedirectHandling().disableAuthCaching().build()) {
                final Maskinportenklient maskinportenklient = createClient(String.format("http://localhost:%s/token", client.getLocalPort()), httpClient);
                assertThat(maskinportenklient.getAccessToken(SCOPE)).isEqualTo(OidcMockExpectation.previousJwt);
                // httpClient should not be closed yet, have another go
                assertThat(maskinportenklient.getAccessToken(SCOPE)).isEqualTo(OidcMockExpectation.previousJwt);

            } catch (IOException e) {
                fail("Could not get token using provided client", e);
            }

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
                                            param("grant_type", JWT_BEARER_GRANT)
                                    )
                            ),
                    Times.exactly(1)).respond(callback().withCallbackClass(OidcMockExpectation.class));
            Maskinportenklient maskinportenklient = createClient(String.format("http://localhost:%s/token", client.getLocalPort()));
            final String accessToken = maskinportenklient.getAccessToken(SCOPE);
            assertThat(accessToken).isEqualTo(OidcMockExpectation.previousJwt);
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
                                                    param("grant_type", JWT_BEARER_GRANT)
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

    @DisplayName("Generate access token fails. Maskinporten returns temporarily unavailable.")
    @Test
    void getAccessTokenFailsTemporarilyUnavailable() {
        try (final ClientAndServer client = ClientAndServer.startClientAndServer()) {
            client.when(
                            request()
                                    .withSecure(false)
                                    .withMethod(HttpMethod.POST.name())
                                    .withPath("/token")
                                    .withBody(
                                            params(
                                                    param("grant_type", JWT_BEARER_GRANT)
                                            )
                                    ),
                            Times.exactly(1))
                    .respond(response()
                            .withBody("FAILURE WAS AN OPTION AFTER ALL")
                            .withStatusCode(HttpStatusCode.SERVICE_UNAVAILABLE_503.code()));

            Maskinportenklient maskinportenklient = createClient(String.format("http://localhost:%s/token", client.getLocalPort()));
            final MaskinportenTokenTemporarilyUnavailableException exception = catchThrowableOfType(() -> maskinportenklient.getAccessToken(SCOPE), MaskinportenTokenTemporarilyUnavailableException.class);
            assertThat(exception.getStatusCode()).isEqualTo(HttpStatusCode.SERVICE_UNAVAILABLE_503.code());
        }
    }

    @DisplayName("Generate access token fails due to a connection failure")
    @Timeout(value = 60)
    @Test
    void getAccessTokenNetworkFailure() throws IOException {
        int localport;
        try (ServerSocket s = new ServerSocket(0)) {
            localport = s.getLocalPort();
        }
        final Maskinportenklient maskinportenklient = createClient(String.format("http://localhost:%s/token", localport));
        final RuntimeException runtimeException = catchThrowableOfType(() -> maskinportenklient.getAccessToken(SCOPE), RuntimeException.class);
        assertThat(runtimeException.getCause()).isInstanceOf(HttpHostConnectException.class);

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
                                            param("grant_type", JWT_BEARER_GRANT)
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
                                            param("grant_type", JWT_BEARER_GRANT)
                                    )
                            )
            ).respond(callback().withCallbackClass(OidcMockExpectation.class));
            Maskinportenklient maskinportenklient = createClient(String.format("http://localhost:%s/token", client.getLocalPort()));
            assertThat(maskinportenklient.getDelegatedAccessToken(consumerOrg, SCOPE)).isEqualTo(OidcMockExpectation.previousJwt);
        }

    }

    @DisplayName("Generate token with audience")
    @Test
    void getAccessTokenWithAudience() throws ParseException {
        final String audience = UUID.randomUUID().toString();
        try (final ClientAndServer client = ClientAndServer.startClientAndServer()) {
            client.when(
                    request()
                            .withSecure(false)
                            .withMethod(HttpMethod.POST.name())
                            .withPath("/token")
                            .withBody(
                                    params(
                                            param("grant_type", JWT_BEARER_GRANT)
                                    )
                            )
            ).respond(callback().withCallbackClass(OidcMockExpectation.class));
            final Maskinportenklient maskinportenklient = createClient(String.format("http://localhost:%s/token", client.getLocalPort()));

            final String accessToken = maskinportenklient.getAccessTokenWithAudience(audience, SCOPE);
            assertThat(accessToken).isEqualTo(OidcMockExpectation.previousJwt);
            SignedJWT jwt = SignedJWT.parse(accessToken);
            assertThat(jwt.getJWTClaimsSet().getAudience()).isEqualTo(Collections.singletonList(audience));
        }
    }

    @DisplayName("Generate end-user-restricted token")
    @Test
    void getEndUserRestrictedAccessToken() throws ParseException {
        final String audience = UUID.randomUUID().toString();
        final String pid = "16032826532";
        try (final ClientAndServer client = ClientAndServer.startClientAndServer()) {
            client.when(
                    request()
                            .withSecure(false)
                            .withMethod(HttpMethod.POST.name())
                            .withPath("/token")
                            .withBody(
                                    params(
                                            param("grant_type", JWT_BEARER_GRANT)
                                    )
                            )
            ).respond(callback().withCallbackClass(OidcMockExpectation.class));
            final Maskinportenklient maskinportenklient = createClient(String.format("http://localhost:%s/token", client.getLocalPort()));

            final AccessTokenRequest request = new AccessTokenRequestBuilder().scope(SCOPE).audience(audience).pid(pid).build();
            final String accessToken = maskinportenklient.getAccessToken(request);
            assertThat(accessToken).isEqualTo(OidcMockExpectation.previousJwt);
            SignedJWT jwt = SignedJWT.parse(accessToken);
            assertThat(jwt.getJWTClaimsSet().getClaim("pid")).isEqualTo(pid);
        }
    }


    private Maskinportenklient createClient(final String tokenEndpoint) {
        return createMaskinportenklient(createVirksomhetSertifikater().requireAuthKeyStore(), MaskinportenklientProperties.builder()
                .audience("https://ver2.maskinporten.no/")
                .tokenEndpoint(tokenEndpoint)
                .issuer("77c0a0ba-d20d-424c-b5dd-f1c63da07fc4")
                .numberOfSecondsLeftBeforeExpire(10)
                .timeoutMillis(1000)
                .build(), null);
    }

    private Maskinportenklient createClientWithObservability(final String tokenEndpoint, final MaskinportenKlientObservability maskinportenKlientObservability) {
        return createMaskinportenklient(createVirksomhetSertifikater().requireAuthKeyStore(), MaskinportenklientProperties.builder()
                .audience("https://ver2.maskinporten.no/")
                .tokenEndpoint(tokenEndpoint)
                .issuer("77c0a0ba-d20d-424c-b5dd-f1c63da07fc4")
                .numberOfSecondsLeftBeforeExpire(10)
                .timeoutMillis(1000)
                .build(), maskinportenKlientObservability);
    }

    private Maskinportenklient createClient(final String tokenEndpoint, final CloseableHttpClient client) {

        return createMaskinportenklient(createVirksomhetSertifikater().requireAuthKeyStore(), MaskinportenklientProperties.builder()
                .audience("https://ver2.maskinporten.no/")
                .tokenEndpoint(tokenEndpoint)
                .issuer("77c0a0ba-d20d-424c-b5dd-f1c63da07fc4")
                .numberOfSecondsLeftBeforeExpire(10)
                .timeoutMillis(1000)
                .providedHttpClient(client)
                .build(), null);

    }

    private Maskinportenklient createMaskinportenklient(final VirksomhetSertifikater.KsVirksomhetSertifikatStore authKeyStore,
                                                        final MaskinportenklientProperties maskinportenklientProperties,
                                                        final MaskinportenKlientObservability maskinportenKlientObservability) {
        MaskinportenklientBuilder builder = Maskinportenklient.builder()
                .withPrivateKey(authKeyStore.getPrivateKey())
                .withProperties(maskinportenklientProperties);

        int random = ThreadLocalRandom.current().nextInt(0, 3);
        switch (random) {
            case 0 -> builder.usingAsymmetricKey(UUID.randomUUID().toString());
            case 1 -> builder.usingVirksomhetssertifikat(authKeyStore.getCertificate());
            default -> builder.usingJwsHeaderProvider(() -> new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .keyID(UUID.randomUUID().toString())
                    .build());
        }
        if (maskinportenKlientObservability != null) {
            builder.havingObservabilitySupport(maskinportenKlientObservability);
        }


        return builder.build();
    }


    private VirksomhetSertifikater createVirksomhetSertifikater() {
        return new VirksomhetSertifikater(Collections.singleton(new Sertifikat(
                SertifikatType.AUTH,
                "KS_PASSWORD",
                Resources.getResource("KS-virksomhetssertifikat-auth.p12").getPath(),
                "authentication certificate",
                "authentication certificate",
                "KS_PASSWORD"
        )));
    }

}