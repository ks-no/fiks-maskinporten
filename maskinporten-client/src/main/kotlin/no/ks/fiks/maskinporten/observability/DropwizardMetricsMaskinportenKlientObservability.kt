package no.ks.fiks.maskinporten.observability

import com.codahale.metrics.MetricRegistry
import com.codahale.metrics.httpclient5.InstrumentedHttpClients
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder
import org.apache.hc.client5.http.io.HttpClientConnectionManager

/**
 * Adds observability to MaskinportenKlient using Dropwizard Metrics (https://metrics.dropwizard.io)
 */
class DropwizardMetricsMaskinportenKlientObservability(private val metricRegistry: MetricRegistry) : MaskinportenKlientObservability {
    override fun createObservableHttpClientBuilder(): HttpClientBuilder = InstrumentedHttpClients.custom(metricRegistry)

    override fun addObservabilityToConnectionManager(httpClientConnectionManager: HttpClientConnectionManager): HttpClientConnectionManager {
        // Dropwizard Metrics sets up observability for the connection manager automatically
        return httpClientConnectionManager
    }
}