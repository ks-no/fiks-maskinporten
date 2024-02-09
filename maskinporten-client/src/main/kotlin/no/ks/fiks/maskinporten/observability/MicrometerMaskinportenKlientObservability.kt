package no.ks.fiks.maskinporten.observability

import io.micrometer.core.instrument.MeterRegistry
import io.micrometer.core.instrument.binder.MeterBinder
import io.micrometer.core.instrument.binder.httpcomponents.hc5.ObservationExecChainHandler
import io.micrometer.core.instrument.binder.httpcomponents.hc5.PoolingHttpClientConnectionManagerMetricsBinder
import io.micrometer.observation.ObservationRegistry
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager
import org.apache.hc.client5.http.io.HttpClientConnectionManager

private val log = mu.KotlinLogging.logger {  }
/**
 * Adds observability to MaskinportenKlient using Micrometer (https://micrometer.io/)
 */
class MicrometerMaskinportenKlientObservability(private val observationRegistry: ObservationRegistry?) : MaskinportenKlientObservability, MeterBinder {
    private var connectionManagerMeterBuilder: PoolingHttpClientConnectionManagerMetricsBinder? = null

    override fun createObservableHttpClientBuilder(): HttpClientBuilder {
        return HttpClientBuilder.create().apply {
            observationRegistry?.run {
                log.debug { "Enabling micrometer-tracing support for the httpclient" }
                addExecInterceptorLast("micrometer", ObservationExecChainHandler(this))
            }
        }
    }

    override fun addObservabilityToConnectionManager(httpClientConnectionManager: HttpClientConnectionManager): HttpClientConnectionManager {
        if (httpClientConnectionManager is PoolingHttpClientConnectionManager) {
            val metricsBinder = PoolingHttpClientConnectionManagerMetricsBinder(httpClientConnectionManager, "maskinporten.client")
            connectionManagerMeterBuilder = metricsBinder
        }
        return httpClientConnectionManager
    }

    override fun bindTo(registry: MeterRegistry) {
        connectionManagerMeterBuilder?.bindTo(registry)
    }

    companion object {
        @JvmStatic
        fun builder(): MicrometerMaskinportenKlientObservabilityBuilder = MicrometerMaskinportenKlientObservabilityBuilder()
    }


}

class MicrometerMaskinportenKlientObservabilityBuilder {
    private var observationRegistry: ObservationRegistry? = null

    fun withObservationRegistry(observationRegistry: ObservationRegistry) = apply { this.observationRegistry = observationRegistry }

    fun build() = MicrometerMaskinportenKlientObservability(observationRegistry)
}