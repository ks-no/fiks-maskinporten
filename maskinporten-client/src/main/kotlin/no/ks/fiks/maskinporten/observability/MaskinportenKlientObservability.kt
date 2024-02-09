package no.ks.fiks.maskinporten.observability

import org.apache.hc.client5.http.impl.classic.HttpClientBuilder
import org.apache.hc.client5.http.io.HttpClientConnectionManager

/**
 * Interface for observability of MaskinportenKlient
 * Implementations of this interface can be used to add observability to MaskinportenKlient
 * @see MicrometerMaskinportenKlientObservability
 * @see DropwizardMetricsMaskinportenKlientObservability
 */
interface MaskinportenKlientObservability {

    fun createObservableHttpClientBuilder(): HttpClientBuilder

    fun addObservabilityToConnectionManager(httpClientConnectionManager: HttpClientConnectionManager): HttpClientConnectionManager

}