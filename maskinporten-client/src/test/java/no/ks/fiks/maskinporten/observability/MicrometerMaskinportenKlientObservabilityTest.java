package no.ks.fiks.maskinporten.observability;

import io.micrometer.core.instrument.observation.DefaultMeterObservationHandler;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import io.micrometer.observation.ObservationRegistry;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.io.BasicHttpClientConnectionManager;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class MicrometerMaskinportenKlientObservabilityTest {

    @DisplayName("Create observable http client builder without tracing")
    @Test
    void createObservableHttpClientBuilderWithoutTracing() {
        final var meterRegistry = new SimpleMeterRegistry();
        final MicrometerMaskinportenKlientObservability maskinportenKlientObservability =
                MicrometerMaskinportenKlientObservability.builder()
                        .build();
        final HttpClientBuilder observableHttpClientBuilder = maskinportenKlientObservability.createObservableHttpClientBuilder();
        maskinportenKlientObservability.bindTo(meterRegistry);
        assertThat(observableHttpClientBuilder.build())
                .satisfies(httpClient -> assertThat(httpClient).isNotNull());
    }

    @DisplayName("Create observable http client builder with tracing")
    @Test
    void createObservableHttpClientBuilderWithTracing() {
        final var meterRegistry = new SimpleMeterRegistry();
        final ObservationRegistry observationRegistry = ObservationRegistry.create();
        observationRegistry.observationConfig().observationHandler(new DefaultMeterObservationHandler(meterRegistry));
        final MicrometerMaskinportenKlientObservability maskinportenKlientObservability =
                MicrometerMaskinportenKlientObservability.builder()
                        .withObservationRegistry(observationRegistry)
                        .build();
        maskinportenKlientObservability.bindTo(meterRegistry);
        final HttpClientBuilder observableHttpClientBuilder = maskinportenKlientObservability.createObservableHttpClientBuilder();
        assertThat(observableHttpClientBuilder.build()).satisfies(httpClient -> {
            assertThat(httpClient).isNotNull();
        });
    }

    @DisplayName("Add observability to pooling connection manager")
    @Test
    void addToConnectionManager() {
        final var meterRegistry = new SimpleMeterRegistry();
        final MicrometerMaskinportenKlientObservability maskinportenKlientObservability =
                MicrometerMaskinportenKlientObservability.builder()
                        .build();
        try(final var connectionManager = PoolingHttpClientConnectionManagerBuilder.create().setMaxConnTotal(20).build()) {
            maskinportenKlientObservability.addObservabilityToConnectionManager(connectionManager);
            maskinportenKlientObservability.bindTo(meterRegistry);
            assertThat(meterRegistry).satisfies(registry -> {
                assertThat(registry.getMeters()).isNotEmpty();
                assertThat(registry.get("httpcomponents.httpclient.pool.total.max")).satisfies(meter -> {
                    assertThat(meter).isNotNull();
                    assertThat(meter.gauge().value()).isEqualTo(20.0d);
                });
            });
        }
        meterRegistry.close();
    }

    @DisplayName("Non-pooling connection manager cannot generate metrics")
    @Test
    void addToNonPoolingConnectionManger() {
        final var meterRegistry = new SimpleMeterRegistry();
        final MicrometerMaskinportenKlientObservability maskinportenKlientObservability =
                MicrometerMaskinportenKlientObservability.builder()
                        .build();
        try(var connectionManager = new BasicHttpClientConnectionManager()) {
            maskinportenKlientObservability.addObservabilityToConnectionManager(connectionManager);
        }
        maskinportenKlientObservability.bindTo(meterRegistry);
        assertThat(meterRegistry.getMeters()).isEmpty();
        meterRegistry.close();
    }
}
