package no.ks.fiks.maskinporten.observability

import io.micrometer.core.instrument.MeterRegistry
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
class MicrometerMaskinportenKlientObservability(private val observationRegistry: ObservationRegistry?, private val meterRegistry: MeterRegistry) : MaskinportenKlientObservability {
    private var connectionManagerMeterBuilder: PoolingHttpClientConnectionManagerMetricsBinder? = null

    override fun createObservableHttpClientBuilder(): HttpClientBuilder {
        return HttpClientBuilder.create().apply {
            log.debug { "Enabling micrometer-tracing support for the httpclient" }
            observationRegistry?.run { addExecInterceptorLast("micrometer", ObservationExecChainHandler(this))  }
        }
    }

    override fun addObservabilityToConnectionManager(httpClientConnectionManager: HttpClientConnectionManager): HttpClientConnectionManager {
        if (httpClientConnectionManager is PoolingHttpClientConnectionManager) {
            val metricsBinder = PoolingHttpClientConnectionManagerMetricsBinder(httpClientConnectionManager, "maskinporten.client")
            metricsBinder.bindTo(meterRegistry)
            connectionManagerMeterBuilder = metricsBinder
        }
        return httpClientConnectionManager
    }

    companion object {
        @JvmStatic
        fun builder(): MicrometerMaskinportenKlientObservabilityBuilder = MicrometerMaskinportenKlientObservabilityBuilder()
    }


}

class MicrometerMaskinportenKlientObservabilityBuilder {
    private var observationRegistry: ObservationRegistry? = null
    private var meterRegistry: MeterRegistry? = null

    fun withObservationRegistry(observationRegistry: ObservationRegistry) = apply { this.observationRegistry = observationRegistry }

    fun withMeterRegistry(meterRegistry: MeterRegistry) = apply { this.meterRegistry = meterRegistry }

    fun build() = MicrometerMaskinportenKlientObservability(observationRegistry, meterRegistry ?: error("MeterRegistry is required"))
}