package no.ks.fiks.maskinporten

import io.kotest.assertions.asClue
import io.kotest.assertions.throwables.shouldThrowExactly
import io.kotest.core.spec.style.StringSpec
import io.kotest.matchers.nulls.beNull
import io.kotest.matchers.should
import io.kotest.matchers.shouldBe
import io.kotest.matchers.throwable.shouldHaveMessage

internal class MaskinportenPropertiesTest : StringSpec({

    "Invokes toMaskinportenklientProperties() when the issuer property is null" {
        shouldThrowExactly<IllegalArgumentException> {
            MaskinportenProperties().toMaskinportenklientProperties()
        } shouldHaveMessage """"issuer" property can not be null"""
    }

    "Invokes toMaskinportenklientProperties() when the audience property is null" {
        shouldThrowExactly<IllegalArgumentException> {
            MaskinportenProperties(issuer = "issuer").toMaskinportenklientProperties()
        } shouldHaveMessage """"audience" property can not be null"""
    }

    "Invokes toMaskinportenklientProperties() when the tokenEndpoint property is null" {
        shouldThrowExactly<IllegalArgumentException> {
            MaskinportenProperties(issuer = "issuer", audience = "audience").toMaskinportenklientProperties()
        } shouldHaveMessage """"tokenEndpoint" property can not be null"""
    }

    "Invokes toMaskinportenklientProperties() when the consumerOrg property is null" {
        val issuer = "issuer"
        val audience = "audience"
        val tokenEndpoint = "https://somewhere"
        MaskinportenProperties(issuer = issuer, audience = audience, tokenEndpoint = tokenEndpoint)
            .toMaskinportenklientProperties()
            .asClue {
                it.issuer shouldBe issuer
                it.audience shouldBe audience
                it.tokenEndpoint shouldBe tokenEndpoint
                it.consumerOrg should beNull()
                it.numberOfSecondsLeftBeforeExpire shouldBe DEFAULT_SECONDS_LEFT_BEFORE_EXPIRATION
                it.timeoutMillis shouldBe DEFAULT_TIMEOUT
            }
    }

    "Invokes toMaskinportenklientProperties() when the consumerOrg property is set" {
        val issuer = "issuer"
        val audience = "audience"
        val tokenEndpoint = "https://somewhere"
        val consumerOrg = "999999999"
        MaskinportenProperties(issuer = issuer, audience = audience, tokenEndpoint = tokenEndpoint, consumerOrg = consumerOrg)
            .toMaskinportenklientProperties().asClue {
                it.issuer shouldBe issuer
                it.audience shouldBe audience
                it.tokenEndpoint shouldBe tokenEndpoint
                it.consumerOrg shouldBe consumerOrg
                it.numberOfSecondsLeftBeforeExpire shouldBe DEFAULT_SECONDS_LEFT_BEFORE_EXPIRATION
                it.timeoutMillis shouldBe DEFAULT_TIMEOUT
            }
    }
})
