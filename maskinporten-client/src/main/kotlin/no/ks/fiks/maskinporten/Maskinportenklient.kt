package no.ks.fiks.maskinporten

import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import mu.withLoggingContext
import net.jodah.expiringmap.ExpirationPolicy
import net.jodah.expiringmap.ExpiringEntryLoader
import net.jodah.expiringmap.ExpiringMap
import net.jodah.expiringmap.ExpiringValue
import no.ks.fiks.maskinporten.error.MaskinportenClientTokenRequestException
import no.ks.fiks.maskinporten.error.MaskinportenTokenRequestException
import org.apache.hc.client5.http.config.RequestConfig
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder
import org.apache.hc.core5.http.*
import org.apache.hc.core5.http.io.HttpClientResponseHandler
import org.apache.hc.core5.http.io.support.ClassicRequestBuilder
import java.io.BufferedReader
import java.io.IOException
import java.io.InputStream
import java.io.InputStreamReader
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.text.ParseException
import java.util.*
import java.util.concurrent.TimeUnit

private val log = mu.KotlinLogging.logger { }

private const val GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer"
private const val CLAIM_SCOPE = "scope"
private const val CLAIM_CONSUMER_ORG = "consumer_org"
private const val CLAIM_RESOURCE = "resource"
private const val CLAIM_PID = "pid"
private const val MDC_JTIID = "jtiId"

private fun scopesToCollection(vararg scopes: String): Collection<String> {
    return scopes.toList()
}

class Maskinportenklient(privateKey: PrivateKey, jwsHeaderProvider: JWSHeaderProvider, private val properties: MaskinportenklientProperties) :
    MaskinportenklientOperations {
    private val jwsHeader: JWSHeader
    private val signer: JWSSigner
    private val map: ExpiringMap<AccessTokenRequest, String>

    @Deprecated("Use JWSHeaderProvider constructor")
    constructor(
        keyStore: KeyStore,
        privateKeyAlias: String?,
        privateKeyPassword: CharArray?,
        properties: MaskinportenklientProperties
    ) : this(
        keyStore.getKey(privateKeyAlias, privateKeyPassword) as PrivateKey,
        keyStore.getCertificate(privateKeyAlias) as X509Certificate,
        properties
    )

    @Deprecated("Use JWSHeaderProvider constructor")
    constructor(
        privateKey: PrivateKey,
        certificate: X509Certificate,
        properties: MaskinportenklientProperties
    ) : this(
        privateKey,
        VirksomhetssertifikatJWSHeaderProvider(certificate),
        properties
    )

    init {
        jwsHeader = jwsHeaderProvider.buildJWSHeader()
        signer = RSASSASigner(privateKey)
        map = ExpiringMap.builder()
            .variableExpiration()
            .expiringEntryLoader(ExpiringEntryLoader { tokenRequest: AccessTokenRequest ->
                val json = parse(
                    doAcquireAccessToken(tokenRequest)
                        ?: throw IllegalArgumentException("Got empty response from provider for request $tokenRequest")
                )
                val accessToken = parseAccessToken(json)
                val expiresIn = getExpiresIn(json)
                val duration = expiresIn - properties.numberOfSecondsLeftBeforeExpire
                val exp = TimeUnit.MILLISECONDS.convert(getExp(accessToken), TimeUnit.SECONDS)
                log.info {
                    "Adding access token to cache; access_token.scopes: '${json[CLAIM_SCOPE]}', access_token.exp: ${Date(exp)}, expires_in: $expiresIn seconds. Expires from cache in $duration seconds (${
                        Date(
                            System.currentTimeMillis() + 1000 * duration
                        )
                    })."
                }
                ExpiringValue(json["access_token"].toString(), ExpirationPolicy.CREATED, duration, TimeUnit.SECONDS)
            } as ExpiringEntryLoader<AccessTokenRequest, String>)
            .build()
    }

    private fun getExpiresIn(json: Map<String, Any>): Long {
        val value = Objects.requireNonNull(json["expires_in"], "JSON response fra Maskinporten mangler felt 'expires_in'")
        return value.toString().toLong()
    }

    private fun getExp(accessToken: Map<String, Any>): Long {
        val value = Objects.requireNonNull(accessToken["exp"], "Access token fra Maskinporten mangler felt 'exp'")
        return value.toString().toLong()
    }

    @Deprecated(
        "Bruk {@link #getAccessToken(AccessTokenRequest)}"
    )
    override fun getAccessToken(scopes: Collection<String>): String {
        return getTokenForRequest(AccessTokenRequest(scopes = scopes.toSet()))
    }

    @Deprecated(
        "Bruk {@link #getAccessToken(AccessTokenRequest)}"
    )
    override fun getAccessToken(vararg scopes: String): String {
        return getAccessToken(scopesToCollection(*scopes))
    }

    @Deprecated(
        "Bruk {@link #getAccessToken(AccessTokenRequest)}"
    )
    override fun getDelegatedAccessToken(consumerOrg: String, scopes: Collection<String>): String {
        return getTokenForRequest(AccessTokenRequest(scopes = scopes.toSet(), consumerOrg = consumerOrg))
    }

    @Deprecated(
        "Bruk {@link #getAccessToken(AccessTokenRequest)}"
    )
    override fun getDelegatedAccessToken(consumerOrg: String, vararg scopes: String): String {
        return getDelegatedAccessToken(consumerOrg, scopesToCollection(*scopes))
    }

    @Deprecated(
        "Bruk {@link #getAccessToken(AccessTokenRequest)}"
    )
    override fun getAccessTokenWithAudience(audience: String, scopes: Collection<String>): String {
        return getTokenForRequest(AccessTokenRequest(scopes = scopes.toSet(), audience = audience))
    }

    @Deprecated(
        """Bruk {@link #getAccessToken(AccessTokenRequest)}
     
      """
    )
    override fun getAccessTokenWithAudience(audience: String, vararg scopes: String): String {
        return getAccessTokenWithAudience(audience, scopesToCollection(*scopes))
    }

    override fun getAccessToken(request: AccessTokenRequest): String {
        return getTokenForRequest(request)
    }

    private fun getTokenForRequest(accessTokenRequest: AccessTokenRequest): String {
        require(accessTokenRequest.scopes.isNotEmpty()) { "Minst ett scope må oppgies" }
        return map[accessTokenRequest] ?: throw IllegalStateException("En ukjent feil skjedde ved forsøk på å hente token fra Maskinporten")
    }

    @Throws(JOSEException::class)
    private fun createJwtRequestForAccessToken(accessTokenRequest: AccessTokenRequest, jtiId: String?): String {
        val issuedTimeInMillis = System.currentTimeMillis()
        val expirationTimeInMillis = issuedTimeInMillis + TimeUnit.MILLISECONDS.convert(2, TimeUnit.MINUTES)
        val audience = properties.audience
        val issuer = properties.issuer
        val claimScopes = accessTokenRequest.scopes.joinToString(" ")
        val consumerOrg = accessTokenRequest.consumerOrg ?: properties.consumerOrg
        log.debug { "Signing JWTRequest with audience='$audience',issuer='$issuer',scopes='$claimScopes',consumerOrg='$consumerOrg', jtiId='$jtiId'" }
        val claimBuilder = JWTClaimsSet.Builder()
            .audience(audience)
            .issuer(issuer)
            .claim(CLAIM_SCOPE, claimScopes)
            .jwtID(jtiId)
            .issueTime(Date(issuedTimeInMillis))
            .expirationTime(Date(expirationTimeInMillis))
        consumerOrg?.run { claimBuilder.claim(CLAIM_CONSUMER_ORG, this) }
        accessTokenRequest.audience?.run { claimBuilder.claim(CLAIM_RESOURCE, this) }
        accessTokenRequest.pid?.run { claimBuilder.claim(CLAIM_PID, this) }
        val signedJWT = SignedJWT(
            jwsHeader, claimBuilder
                .build()
        )
        signedJWT.sign(signer)
        return signedJWT.serialize()
    }

    private fun doAcquireAccessToken(accessTokenRequest: AccessTokenRequest): String? {
        return try {
            acquireAccessToken(accessTokenRequest)
        } catch (e: JOSEException) {
            log.error(e) { "Could not acquire access token due to an exception" }
            throw RuntimeException(e)
        } catch (e: IOException) {
            log.error(e) { "Could not acquire access token due to an exception" }
            throw RuntimeException(e)
        }
    }

    @Throws(JOSEException::class, IOException::class)
    private fun acquireAccessToken(accessTokenRequest: AccessTokenRequest): String? {
        val jtiId = UUID.randomUUID().toString()
        withLoggingContext(MDC_JTIID to jtiId) {
            val postData = "grant_type={grant_type}&assertion={assertion}"
                .replace("{grant_type}", GRANT_TYPE)
                .replace("{assertion}", createJwtRequestForAccessToken(accessTokenRequest, jtiId))
                .toByteArray(StandardCharsets.UTF_8)
            val tokenEndpointUrlString = properties.tokenEndpoint
            log.debug { """Acquiring access token from "$tokenEndpointUrlString"""" }
            val startTime = System.currentTimeMillis()
            return actuallyExecuteRequest { httpClient ->
                httpClient.execute(createHttpRequest(postData), object : HttpClientResponseHandler<String?> {
                    override fun handleResponse(classicHttpResponse: ClassicHttpResponse): String? {
                        val responseCode = classicHttpResponse.code
                        log.debug { "Access token response received in ${System.currentTimeMillis() - startTime} ms with status $responseCode" }
                        return if (HttpStatus.SC_OK == responseCode) {
                            classicHttpResponse.entity.content?.use { contentStream -> contentStream.readCompletelyAsString() }
                        } else {
                            val errorFromMaskinporten: String = classicHttpResponse.entity.content.use { errorContentStream ->
                                errorContentStream.readCompletelyAsString()
                            }
                            log.warn { "Failed to get token: $errorFromMaskinporten" }
                            val exceptionMessage = "Http response code: $responseCode, url: '$tokenEndpointUrlString', message: '$errorFromMaskinporten'"
                            if (responseCode >= HttpStatus.SC_BAD_REQUEST && responseCode < HttpStatus.SC_INTERNAL_SERVER_ERROR) {
                                throw MaskinportenClientTokenRequestException(exceptionMessage, responseCode, errorFromMaskinporten)
                            } else {
                                throw MaskinportenTokenRequestException(exceptionMessage, responseCode, errorFromMaskinporten)
                            }
                        }
                    }

                    @Throws(IOException::class)
                    private fun InputStream.readCompletelyAsString() = InputStreamReader(this).use { isr ->
                        BufferedReader(isr).use { br ->
                            br.lineSequence().joinToString("\n")
                        }
                    }

                })
            }
        }
    }

    private fun actuallyExecuteRequest(httpRequestResponse: (CloseableHttpClient) -> String?): String? =
        properties.providedHttpClient?.let { httpClient ->
            log.debug { "Executing request using provided httpClient" }
            httpRequestResponse(httpClient)
        } ?: HttpClientBuilder.create()
            .disableAutomaticRetries()
            .disableRedirectHandling()
            .disableAuthCaching()
            .setDefaultRequestConfig(RequestConfig.custom().setConnectionRequestTimeout(properties.timeoutMillis.toLong(), TimeUnit.MILLISECONDS).build())
            .build().use {
                httpRequestResponse(it)
            }


    private fun createHttpRequest(entityBuffer: ByteArray): ClassicHttpRequest {
        return ClassicRequestBuilder.post(properties.tokenEndpoint)
            .setCharset(StandardCharsets.UTF_8)
            .addHeader("Charset", StandardCharsets.UTF_8.name())
            .addHeader(HttpHeaders.CONTENT_TYPE, ContentType.APPLICATION_FORM_URLENCODED.mimeType)
            .setEntity(entityBuffer, ContentType.APPLICATION_FORM_URLENCODED)
            .build()
    }

    private fun parse(value: String): Map<String, Any> {
        return try {
            JSONObjectUtils.parse(value)
        } catch (e: ParseException) {
            throw RuntimeException(e)
        }
    }

    private fun parseAccessToken(json: Map<String, Any>): Map<String, Any> {
        return try {
            val accessToken = Objects.requireNonNull(json["access_token"], "JSON response fra Maskinporten mangler felt 'access_token'")
            JWSObject.parse(accessToken.toString())
                .payload
                .toJSONObject()
        } catch (e: ParseException) {
            throw RuntimeException(e)
        }
    }

    companion object {
        @JvmStatic
        fun builder() = MaskinportenklientBuilder()
    }
}

class MaskinportenklientBuilder {
    private var privateKey: PrivateKey? = null
    private var jwsHeaderProvider: JWSHeaderProvider? = null
    private var properties: MaskinportenklientProperties? = null

    fun withPrivateKey(privateKey: PrivateKey) = this.also { this.privateKey = privateKey }

    fun withProperties(properties: MaskinportenklientProperties) = this.also { this.properties = properties }

    fun usingVirksomhetssertifikat(certificate: X509Certificate) = this.also {
        if (this.jwsHeaderProvider != null) throw throw IllegalArgumentException("""Can not configure client with virksomhetssertifikat or asymmetric key more than once""")
        this.jwsHeaderProvider = VirksomhetssertifikatJWSHeaderProvider(certificate)
    }

    fun usingAsymmetricKey(keyId: String) = this.also {
        if (this.jwsHeaderProvider != null) throw throw IllegalArgumentException("""Can not configure client with virksomhetssertifikat or asymmetric key more than once""")
        this.jwsHeaderProvider = AsymmetricKeyJWSHeaderProvider(keyId)
    }

    fun build() : Maskinportenklient = Maskinportenklient(
        privateKey ?: throw IllegalArgumentException("""The "privateKey" property can not be null"""),
        jwsHeaderProvider ?: throw IllegalArgumentException("""Must configure client to use either virksomhetssertifikat or asymmetric key"""),
        properties ?: throw IllegalArgumentException("""The "properties" property can not be null"""),
    )
}
