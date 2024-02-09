package no.ks.fiks.maskinporten.observability

import org.apache.hc.client5.http.impl.classic.HttpClientBuilder
import org.apache.hc.client5.http.io.HttpClientConnectionManager

/**
 * Default observability for MaskinportenKlient
 */
class DefaultMaskinportenKlientObservability : MaskinportenKlientObservability {
    override fun createObservableHttpClientBuilder(): HttpClientBuilder = HttpClientBuilder.create()

    override fun addObservabilityToConnectionManager(httpClientConnectionManager: HttpClientConnectionManager): HttpClientConnectionManager = httpClientConnectionManager
}