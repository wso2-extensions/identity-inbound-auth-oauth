/*
 * Copyright (c) 2012, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.token.handlers.grant.saml;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.validation.ValidationException;
import org.w3c.dom.NodeList;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AbstractAuthorizationGrantHandler;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.util.X509CredentialImpl;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * This implements SAML 2.0 Bearer Assertion Profile for OAuth 2.0 -
 * http://tools.ietf.org/html/draft-ietf-oauth-saml2-bearer-14.
 */
public class SAML2BearerGrantHandler extends AbstractAuthorizationGrantHandler {

    public static final String ASSERTION_ELEMENT = "Assertion";
    public static final String IDP_ENTITY_ID = "IdPEntityId";
    private static Log log = LogFactory.getLog(SAML2BearerGrantHandler.class);
    private static final String SAMLSSO_AUTHENTICATOR = "samlsso";
    private static final String SAML2SSO_AUTHENTICATOR_NAME = "SAMLSSOAuthenticator";

    SAMLSignatureProfileValidator profileValidator = null;

    @Override
    public void init() throws IdentityOAuth2Exception {

        super.init();

        Thread thread = Thread.currentThread();
        ClassLoader loader = thread.getContextClassLoader();
        thread.setContextClassLoader(this.getClass().getClassLoader());

        try {
            DefaultBootstrap.bootstrap();
        } catch (ConfigurationException e) {
            log.error("Error in bootstrapping the OpenSAML2 library", e);
            throw new IdentityOAuth2Exception("Error in bootstrapping the OpenSAML2 library");
        } finally {
            thread.setContextClassLoader(loader);
        }

        profileValidator = new SAMLSignatureProfileValidator();
    }

    /**
     * We're validating the SAML token that we receive from the request. Through the assertion parameter in the POST
     * request. A request format that we handle here looks like,
     * <p/>
     * POST /token.oauth2 HTTP/1.1
     * Host: as.example.com
     * Content-Type: application/x-www-form-urlencoded
     * <p/>
     * grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Asaml2-bearer&
     * assertion=PHNhbWxwOl...[omitted for brevity]...ZT4
     *
     * @param tokReqMsgCtx Token message request context
     * @return true if validation is successful, false otherwise
     * @throws org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception
     */
    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {

        super.validateGrant(tokReqMsgCtx);
        if (log.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.SAML_ASSERTION)) {
            log.debug("Received SAML assertion : " +
                    new String(Base64.decodeBase64(tokReqMsgCtx.getOauth2AccessTokenReqDTO().getAssertion()),
                            StandardCharsets.UTF_8));
        }
        Assertion assertion = getAssertionObject(tokReqMsgCtx);
        validateSubject(tokReqMsgCtx, assertion);
        validateIssuer(tokReqMsgCtx, assertion);
        validateSignature(assertion);

        String tenantDomain = getTenantDomain(tokReqMsgCtx);
        IdentityProvider identityProvider = getIdentityProvider(assertion, tenantDomain);
        validateSignatureAgainstIdpCertificate(assertion, tenantDomain, identityProvider);
        validateConditions(tokReqMsgCtx, assertion, identityProvider, tenantDomain);

        long timestampSkewInMillis = OAuthServerConfiguration.getInstance().getTimeStampSkewInSeconds() * 1000;
        validateAssertionTimeWindow(timestampSkewInMillis, getNotOnOrAfter(assertion), getNotBefore(assertion));
        processSubjectConfirmation(tokReqMsgCtx, assertion, identityProvider, tenantDomain, timestampSkewInMillis);

        /*
          The authorization server MUST verify that the Assertion is valid in all other respects per
          [OASIS.saml-core-2.0-os], such as (but not limited to) evaluating all content within the Conditions
          element including the NotOnOrAfter and NotBefore attributes, rejecting unknown condition types, etc.

          [OASIS.saml-core-2.0-os] - http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
         */
        // TODO: Throw the SAML request through the general SAML2 validation routines

        setValuesInMessageContext(tokReqMsgCtx, assertion, identityProvider, tenantDomain);
        invokeExtension(tokReqMsgCtx);
        return true;
    }

    @Override
    public boolean issueRefreshToken() throws IdentityOAuth2Exception {

        return OAuthServerConfiguration.getInstance()
                .getValueForIsRefreshTokenAllowed(OAuthConstants.OAUTH_SAML2_BEARER_METHOD);
    }

    /**
     * The authorization server MUST verify that the NotOnOrAfter instant has not passed, subject to allowable
     * clock skew between systems.  An invalid NotOnOrAfter instant on the <Conditions> element invalidates the
     * entire Assertion.  An invalid NotOnOrAfter instant on a <SubjectConfirmationData> element only invalidates
     * the individual <SubjectConfirmation>.  The authorization server MAY reject Assertions with a NotOnOrAfter
     * instant that is unreasonably far in the future.  The authorization server MAY ensure that Bearer Assertions
     * are not replayed, by maintaining the set of used ID values for the length of time for which the Assertion
     * would be considered valid based on the applicable NotOnOrAfter instant.
     * @param timestampSkewInMillis
     * @param notOnOrAfterFromConditions
     * @param notBeforeConditions
     * @throws IdentityOAuth2Exception
     */
    private void validateAssertionTimeWindow(long timestampSkewInMillis, DateTime notOnOrAfterFromConditions,
                                                DateTime notBeforeConditions) throws IdentityOAuth2Exception {
        if (!isWithinValidTimeWindow(notOnOrAfterFromConditions, notBeforeConditions, timestampSkewInMillis)) {
            throw new IdentityOAuth2Exception("Assertion is not valid according to the time window provided in Conditions");
        }
    }

    /**
     * The <Subject> element MUST contain at least one <SubjectConfirmation> element that allows the authorization
     * server to confirm it as a Bearer Assertion.  Such a <SubjectConfirmation> element MUST have a Method attribute
     * with a value of "urn:oasis:names:tc:SAML:2.0:cm:bearer". The <SubjectConfirmation> element MUST contain a
     * <SubjectConfirmationData> element, unless the Assertion has a suitable NotOnOrAfter attribute on the
     * <Conditions> element, in which case the <SubjectConfirmationData> element MAY be omitted. When present,
     * the <SubjectConfirmationData> element MUST have a Recipient attribute with a value indicating the token endpoint
     * URL of the authorization server (or an acceptable alias).  The authorization server MUST verify that the
     * value of the Recipient attribute matches the token endpoint URL (or an acceptable alias) to which the
     * Assertion was delivered. The <SubjectConfirmationData> element MUST have a NotOnOrAfter attribute that limits the
     * window during which the Assertion can be confirmed.  The <SubjectConfirmationData> element MAY also contain an
     * Address attribute limiting the client address from which the Assertion can be delivered.  Verification of the
     * Address is at the discretion of the authorization server.
     * @param tokReqMsgCtx
     * @param assertion
     * @param identityProvider
     * @param tenantDomain
     * @param timeSkew
     * @throws IdentityOAuth2Exception
     */
    private void processSubjectConfirmation(OAuthTokenReqMessageContext tokReqMsgCtx, Assertion assertion,
                                            IdentityProvider identityProvider, String tenantDomain, long timeSkew)
            throws IdentityOAuth2Exception {
        boolean bearerFound = false;
        Map<DateTime, DateTime> notOnOrAfterAndNotBeforeFromSubjectConfirmation = new HashMap<>();
        List<String> recipientURLS = new ArrayList<>();
        List<SubjectConfirmation> subjectConfirmations = getSubjectConfirmations(assertion);
        for (SubjectConfirmation subjectConfirmation : subjectConfirmations) {
            bearerFound = updateBearerFound(subjectConfirmation, bearerFound);
            if (subjectConfirmation.getSubjectConfirmationData() != null) {
                recipientURLS = getRecipientUrls(subjectConfirmation.getSubjectConfirmationData());
                notOnOrAfterAndNotBeforeFromSubjectConfirmation =
                        getValidNotBeforeAndAfterDetails(subjectConfirmation.getSubjectConfirmationData(), timeSkew);
            }
        }
        validateBearer(bearerFound);
        String tokenEPAlias = getTokenEPAlias(assertion, identityProvider, tenantDomain);
        validateRecipient(assertion, tokenEPAlias, recipientURLS);
        setValidityPeriod(tokReqMsgCtx, assertion, notOnOrAfterAndNotBeforeFromSubjectConfirmation);
    }

    private void validateBearer(boolean bearerFound) throws IdentityOAuth2Exception {
        if (!bearerFound) {
            throw new IdentityOAuth2Exception("Failed to find a SubjectConfirmation with a Method attribute having : " +
                    OAuthConstants.OAUTH_SAML2_BEARER_METHOD);
        }
    }

    /**
     * The Assertion MUST have an expiry that limits the time window during which it can be used.
     * The expiry can be expressed either as the NotOnOrAfter attribute of the <Conditions> element or as the
     * NotOnOrAfter attribute of a suitable <SubjectConfirmationData> element.
     * @param assertion
     * @param notOnOrAfterAndNotBefore
     * @throws IdentityOAuth2Exception
     */
    private void setValidityPeriod(OAuthTokenReqMessageContext tokReqMsgCtx, Assertion assertion,
                                   Map<DateTime, DateTime> notOnOrAfterAndNotBefore) throws IdentityOAuth2Exception {
        long curTimeInMillis = Calendar.getInstance().getTimeInMillis();
        DateTime notOnOrAfterFromSubjectConfirmation = null;
        DateTime notOnOrAfter = getNotOnOrAfter(assertion);
        if (notOnOrAfter != null) {
            tokReqMsgCtx.setValidityPeriod(notOnOrAfter.getMillis() - curTimeInMillis);
        } else if (!notOnOrAfterAndNotBefore.isEmpty()) {
            if (log.isDebugEnabled()) {
                log.debug("NotOnORAfter details are not found in Conditions. Evaluating values received in " +
                        "SubjectConfirmationData");
            }
            for (Map.Entry<DateTime, DateTime> entry : notOnOrAfterAndNotBefore.entrySet()) {
                if (isSubjectConfirmationTimeWindowIncludedInConditionsTimeWindow(notOnOrAfter,
                        getNotBefore(assertion), entry)) {
                    notOnOrAfterFromSubjectConfirmation = entry.getKey();
                }
            }
            if (notOnOrAfterFromSubjectConfirmation != null) {
                tokReqMsgCtx.setValidityPeriod(notOnOrAfterFromSubjectConfirmation.getMillis() - curTimeInMillis);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Valid NotOnORAfter details are not found in SubjectConfirmation");
                }
                throw new IdentityOAuth2Exception("Cannot find valid NotOnOrAfter details in assertion");
            }
        } else {
            throw new IdentityOAuth2Exception("Cannot find valid NotOnOrAfter details in assertion");
        }
    }

    /**
     * NotBefore and NotOnOrAfter attributes, if present in <SubjectConfirmationData>,
     * SHOULD fall within the overall assertion validity period as specified by the <Conditions> element's
     * NotBefore and NotOnOrAfter attributes
     * @param notOnOrAfter
     * @param notBefore
     * @param entry
     * @return
     */
    private boolean isSubjectConfirmationTimeWindowIncludedInConditionsTimeWindow(DateTime notOnOrAfter,
                                                                                  DateTime notBefore,
                                                                                  Map.Entry<DateTime, DateTime> entry) {
        if (notOnOrAfter != null && notOnOrAfter.isBefore(entry.getKey())) {
            if (log.isDebugEnabled()) {
                log.debug("Conditions has earlier expiry than SubjectConfirmationData");
            }
            return false;
        }

        if (notBefore != null && entry.getValue() != null && notBefore.isAfter(entry.getValue())) {
            if (log.isDebugEnabled()) {
                log.debug("NotBefore in SubjectConfirmationData has earlier value than NotBefore in Conditions");
            }
            return false;
        }
        return true;
    }

    private void validateRecipient(Assertion assertion, String tokenEndpointAlias,
                                   List<String> recipientURLS) throws IdentityOAuth2Exception {
        if (CollectionUtils.isNotEmpty(recipientURLS) && !recipientURLS.contains(tokenEndpointAlias)) {
            if (log.isDebugEnabled()){
                log.debug("None of the recipient URLs match against the token endpoint alias : " + tokenEndpointAlias);
            }
            throw new IdentityOAuth2Exception("Recipient validation failed");
        }
    }

    private void setValuesInMessageContext(OAuthTokenReqMessageContext tokReqMsgCtx, Assertion assertion,
                                           IdentityProvider identityProvider, String tenantDomain)
            throws IdentityOAuth2Exception {
        setUserInMessageContext(tokReqMsgCtx, identityProvider, assertion, tenantDomain);
        tokReqMsgCtx.setScope(tokReqMsgCtx.getOauth2AccessTokenReqDTO().getScope());
        // Storing the Assertion. This will be used in OpenID Connect for example
        tokReqMsgCtx.addProperty(OAuthConstants.OAUTH_SAML2_ASSERTION, assertion);
    }

    private void invokeExtension(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {
        // Invoking extension
        SAML2TokenCallbackHandler callback = OAuthServerConfiguration.getInstance().getSAML2TokenCallbackHandler();
        if (callback != null) {
            if (log.isDebugEnabled()){
                log.debug("Invoking the SAML2 Token callback handler");
            }
            callback.handleSAML2Token(tokReqMsgCtx);
        }
    }

    protected void validateSignatureAgainstIdpCertificate(Assertion assertion, String tenantDomain,
                                                        IdentityProvider identityProvider) throws IdentityOAuth2Exception {
        X509Certificate x509Certificate = getIdpCertificate(tenantDomain, identityProvider);
        try {
            X509Credential x509Credential = new X509CredentialImpl(x509Certificate);
            SignatureValidator signatureValidator = new SignatureValidator(x509Credential);
            signatureValidator.validate(assertion.getSignature());
        } catch (ValidationException e) {
            throw new IdentityOAuth2Exception("Error while validating the signature.", e);
        }
    }

    private X509Certificate getIdpCertificate(String tenantDomain, IdentityProvider identityProvider)
            throws IdentityOAuth2Exception {
        X509Certificate x509Certificate;
        try {
            x509Certificate = (X509Certificate) IdentityApplicationManagementUtil
                    .decodeCertificate(identityProvider.getCertificate());
        } catch (CertificateException e) {
            throw new IdentityOAuth2Exception("Error occurred while decoding public certificate of Identity Provider "
                    + identityProvider.getIdentityProviderName() + " for tenant domain " + tenantDomain, e);
        }
        return x509Certificate;
    }

    /**
     * The Assertion MUST be digitally signed by the issuer and the authorization server MUST verify the signature.
     * @param assertion
     * @throws IdentityOAuth2Exception
     */
    private void validateSignature(Assertion assertion) throws IdentityOAuth2Exception {
        try {
            profileValidator.validate(assertion.getSignature());
        } catch (ValidationException e) {
            throw new IdentityOAuth2Exception("Signature do not adhere to the SAML signature profile.", e);
        }
    }

    private Map<DateTime, DateTime> getValidNotBeforeAndAfterDetails(SubjectConfirmationData subjectConfirmationData,
                                                                     long timeSkew) throws IdentityOAuth2Exception {

        Map<DateTime, DateTime> timeConstrainsFromSubjectConfirmation = new HashMap<>();
        DateTime notOnOrAfter = subjectConfirmationData.getNotOnOrAfter();
        DateTime notBefore = subjectConfirmationData.getNotBefore();

        if (isWithinValidTimeWindow(notOnOrAfter, notBefore, timeSkew)) {
            if (notOnOrAfter != null) {
                timeConstrainsFromSubjectConfirmation.put(notOnOrAfter, notBefore);
            } else {
                if (log.isDebugEnabled()){
                    log.debug("Cannot find valid NotOnOrAfter and NotBefore attributes in " +
                            "SubjectConfirmationData " +
                            subjectConfirmationData.toString());
                }
            }
        }
        return timeConstrainsFromSubjectConfirmation;
    }

    private List<String> getRecipientUrls(SubjectConfirmationData subjectConfirmationData) {
        List<String> recipientURLS = new ArrayList<>();
        if (subjectConfirmationData.getRecipient() != null) {
            recipientURLS.add(subjectConfirmationData.getRecipient());
        }
        return recipientURLS;
    }

    private DateTime getNotBefore(Assertion assertion) {
        return assertion.getConditions().getNotBefore();
    }

    private DateTime getNotOnOrAfter(Assertion assertion) {
        return assertion.getConditions().getNotOnOrAfter();
    }

    private boolean isWithinValidTimeWindow(DateTime notOnOrAfterFromConditions, DateTime notBeforeConditions,
                                         long timestampSkewInMillis) throws IdentityOAuth2Exception {
        if (notOnOrAfterFromConditions != null && isExpired(notOnOrAfterFromConditions, timestampSkewInMillis)) {
            if (log.isDebugEnabled()) {
                log.debug("NotOnOrAfter :" + notOnOrAfterFromConditions + ". Assertion is not valid anymore");
            }
            return false;
        }
        if (isBeforeValidPeriod(notBeforeConditions, timestampSkewInMillis)) {
            // notBefore is an early timestamp
            if (log.isDebugEnabled()) {
                log.debug("NotBefore :" + notBeforeConditions + ". Assertion is not valid during this time");
            }
            return false;
        }
        return true;
    }

    private boolean isBeforeValidPeriod(DateTime notBeforeConditions, long timestampSkewInMillis) {
        return notBeforeConditions != null && notBeforeConditions.minus(timestampSkewInMillis).isAfterNow();
    }

    private boolean isExpired(DateTime notOnOrAfterFromConditions, long timestampSkewInMillis) {
        return notOnOrAfterFromConditions.plus(timestampSkewInMillis).isBeforeNow();
    }

    private boolean updateBearerFound(SubjectConfirmation subjectConfirmation, boolean bearerFound)
            throws IdentityOAuth2Exception {
        if (subjectConfirmation.getMethod() != null) {
            if (subjectConfirmation.getMethod().equals(OAuthConstants.OAUTH_SAML2_BEARER_METHOD)) {
                bearerFound = true;
            }
        } else {
            if (log.isDebugEnabled()){
                log.debug("Cannot find Method attribute in SubjectConfirmation " + subjectConfirmation.toString());
            }
            throw new IdentityOAuth2Exception("Cannot find Method attribute in SubjectConfirmation");
        }
        return bearerFound;
    }

    private List<SubjectConfirmation> getSubjectConfirmations(Assertion assertion) throws IdentityOAuth2Exception {
        List<SubjectConfirmation> subjectConfirmations = assertion.getSubject().getSubjectConfirmations();
        if (subjectConfirmations == null || subjectConfirmations.isEmpty()) {
            throw new IdentityOAuth2Exception("No SubjectConfirmation exist in Assertion");
        }
        return subjectConfirmations;
    }

    private String getTokenEPAlias(Assertion assertion, IdentityProvider identityProvider, String tenantDomain)
            throws IdentityOAuth2Exception {
        String tokenEndpointAlias;
        if (isResidentIdp(identityProvider)) {
            tokenEndpointAlias = getTokenEPAliasFromResidentIdp(assertion, identityProvider, tenantDomain);
        } else {
            // Get Alias from Federated IDP
            tokenEndpointAlias = identityProvider.getAlias();
        }
        return tokenEndpointAlias;
    }

    /**
     * The Assertion MUST contain <Conditions> element with an <AudienceRestriction> element with an <Audience> element
     * containing a URI reference that identifies the authorization server, or the service provider SAML entity of its
     * controlling domain, as an intended audience.  The token endpoint URL of the authorization server MAY be used as
     * an acceptable value for an <Audience> element.  The authorization server MUST verify that
     * it is an intended audience for the Assertion.
     * @param tokReqMsgCtx
     * @param assertion
     * @param identityProvider
     * @param tenantDomain
     * @return
     * @throws IdentityOAuth2Exception
     */
    private void validateConditions(OAuthTokenReqMessageContext tokReqMsgCtx, Assertion assertion,
                                    IdentityProvider identityProvider, String tenantDomain)
            throws IdentityOAuth2Exception {
        Conditions conditions = assertion.getConditions();
        if (conditions != null) {
            String tokenEndpointAlias = getTokenEPAlias(assertion, identityProvider, tenantDomain);
            validateAudience(identityProvider, conditions, tokenEndpointAlias, tenantDomain);
        } else {
            throw new IdentityOAuth2Exception("SAML Assertion doesn't contain Conditions");
        }
    }

    private boolean validateTokenEPAlias(IdentityProvider identityProvider, String tokenEndpointAlias,
                                         String tenantDomain) throws IdentityOAuth2Exception {
        if (StringUtils.isBlank(tokenEndpointAlias)) {
            if (log.isDebugEnabled()) {
                String errorMsg = "Token Endpoint alias has not been configured in the Identity Provider : "
                        + identityProvider.getIdentityProviderName() + " in tenant : " + tenantDomain;
                log.debug(errorMsg);
            }
            throw new IdentityOAuth2Exception("Token Endpoint alias has not been configured in the Identity Provider");
        }
        return true;
    }

    private boolean validateAudienceRestriction(List<AudienceRestriction> audienceRestrictions) throws IdentityOAuth2Exception {
        if (audienceRestrictions == null || audienceRestrictions.isEmpty()) {
            if (log.isDebugEnabled()) {
                String message = "SAML Assertion doesn't contain AudienceRestrictions";
                log.debug(message);
            }
            throw new IdentityOAuth2Exception("Audience restriction not found in the saml assertion");
        }
        return true;
    }

    private boolean validateAudience(IdentityProvider identityProvider, Conditions conditions,
                                     String tokenEndpointAlias, String tenantDomain) throws IdentityOAuth2Exception {
        validateTokenEPAlias(identityProvider, tokenEndpointAlias, tenantDomain);
        List<AudienceRestriction> audienceRestrictions = conditions.getAudienceRestrictions();
        validateAudienceRestriction(audienceRestrictions);
        boolean audienceFound = false;
        // Checking if tokenEP Alias is found among the audiences
        for (AudienceRestriction audienceRestriction : audienceRestrictions) {
            if (CollectionUtils.isNotEmpty(audienceRestriction.getAudiences())) {
                for (Audience audience : audienceRestriction.getAudiences()) {
                    if (audience.getAudienceURI().equals(tokenEndpointAlias)) {
                        audienceFound = true;
                        break;
                    }
                }
            }
            if (audienceFound) {
                break;
            }
        }
        if (!audienceFound) {
            if (log.isDebugEnabled()) {
                log.debug("SAML Assertion Audience Restriction validation failed against the Audience : " +
                        tokenEndpointAlias + " of Identity Provider : " +
                        identityProvider.getIdentityProviderName() + " in tenant : " + tenantDomain);
            }
            throw new IdentityOAuth2Exception("SAML Assertion Audience Restriction validation failed");
        }
        return true;
    }

    private String getTokenEPAliasFromResidentIdp(Assertion assertion, IdentityProvider identityProvider,
                                                  String tenantDomain) throws IdentityOAuth2Exception {
        String tokenEndpointAlias = null;
        FederatedAuthenticatorConfig[] fedAuthnConfigs = identityProvider.getFederatedAuthenticatorConfigs();
        validateIdpEntityId(assertion, tenantDomain,  getIdpEntityId(fedAuthnConfigs));
        // Get OpenIDConnect authenticator == OAuth
        // authenticator
        FederatedAuthenticatorConfig oauthAuthenticatorConfig =
                IdentityApplicationManagementUtil.getFederatedAuthenticator(fedAuthnConfigs,
                        IdentityApplicationConstants.Authenticator.OIDC.NAME);
        // Get OAuth token endpoint
        Property oauthProperty = IdentityApplicationManagementUtil.getProperty(
                oauthAuthenticatorConfig.getProperties(),
                IdentityApplicationConstants.Authenticator.OIDC.OAUTH2_TOKEN_URL);
        if (oauthProperty != null) {
            tokenEndpointAlias = oauthProperty.getValue();
        }
        return tokenEndpointAlias;
    }

    private boolean validateIdpEntityId(Assertion assertion, String tenantDomain, String idpEntityId) throws IdentityOAuth2Exception {
        if (idpEntityId == null || !assertion.getIssuer().getValue().equals(idpEntityId)) {
            if(log.isDebugEnabled()) {
                log.debug("SAML Token Issuer verification failed against resident Identity Provider " +
                        "in tenant : " + tenantDomain + ". Received : " +
                        assertion.getIssuer().getValue() + ", Expected : " + idpEntityId);
            }
            throw new IdentityOAuth2Exception("Issuer verification failed against resident idp");
        }
        return true;
    }

    private String getIdpEntityId(FederatedAuthenticatorConfig[] fedAuthnConfigs) {
        String idpEntityId = null;
        // Get SAML authenticator
        FederatedAuthenticatorConfig samlAuthenticatorConfig =
                IdentityApplicationManagementUtil.getFederatedAuthenticator(fedAuthnConfigs,
                        IdentityApplicationConstants.Authenticator.SAML2SSO.NAME);
        // Get Entity ID from SAML authenticator
        Property samlProperty = IdentityApplicationManagementUtil.getProperty(
                samlAuthenticatorConfig.getProperties(),
                IdentityApplicationConstants.Authenticator.SAML2SSO.IDP_ENTITY_ID);
        if (samlProperty != null) {
            idpEntityId = samlProperty.getValue();
        }
        return idpEntityId;
    }

    private boolean isResidentIdp(IdentityProvider identityProvider) {
        return IdentityApplicationConstants.RESIDENT_IDP_RESERVED_NAME.equals(
                identityProvider.getIdentityProviderName());
    }

    private IdentityProvider getIdentityProvider(Assertion assertion, String tenantDomain)
            throws IdentityOAuth2Exception {
        try {
            IdentityProvider identityProvider = getIdentityProviderFromManager(assertion, tenantDomain);
            checkNullIdentityProvider(assertion, tenantDomain, identityProvider);
            if (isResidentIdp(identityProvider)) {
                identityProvider = IdentityProviderManager.getInstance().getResidentIdP(tenantDomain);
            }
            if (log.isDebugEnabled()) {
                log.debug("Found an idp with given information. IDP name : " + identityProvider.getIdentityProviderName());
            }
            return identityProvider;
        } catch (IdentityProviderManagementException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error while retrieving identity provider for issuer : " + assertion.getIssuer().getValue() +
                        " for tenantDomain : " + tenantDomain, e);
            }
            throw new IdentityOAuth2Exception("Error while retrieving identity provider");
        }
    }

    private IdentityProvider getIdentityProviderFromManager(Assertion assertion, String tenantDomain)
            throws IdentityProviderManagementException {
        if (log.isDebugEnabled()) {
            log.debug("Retrieving identity provider : " + assertion.getIssuer().getValue() + " for " +
                    "authenticator name " + SAMLSSO_AUTHENTICATOR);
        }
        IdentityProvider identityProvider =
                getIdPByAuthenticatorPropertyValue(assertion, tenantDomain, SAMLSSO_AUTHENTICATOR);
        if (identityProvider == null) {
            if (log.isDebugEnabled()) {
                log.debug("Couldnt find an idp for samlsso authenticator. Hence retrieving " +
                        "identity provider : " + assertion
                        .getIssuer().getValue() + " for " +
                        "authenticator name " + SAML2SSO_AUTHENTICATOR_NAME);
            }
            identityProvider = getIdPByAuthenticatorPropertyValue(assertion, tenantDomain, SAML2SSO_AUTHENTICATOR_NAME);
        }
        return identityProvider;
    }

    private IdentityProvider getIdPByAuthenticatorPropertyValue(Assertion assertion, String tenantDomain,
                                                                String authenticatorProperty)
            throws IdentityProviderManagementException {
        return IdentityProviderManager.getInstance().getIdPByAuthenticatorPropertyValue(IDP_ENTITY_ID,
                        assertion.getIssuer().getValue(), tenantDomain, authenticatorProperty, false);
    }

    private void checkNullIdentityProvider(Assertion assertion, String tenantDomain, IdentityProvider identityProvider)
            throws IdentityOAuth2Exception {
        if (identityProvider == null) {
            if(log.isDebugEnabled()) {
                log.debug("SAML Token Issuer : " + assertion.getIssuer().getValue() +
                        " not registered as a local Identity Provider in tenant : " + tenantDomain);
            }
            throw new IdentityOAuth2Exception("Identity provider is null");
        }
    }

    private boolean validateIssuer(OAuthTokenReqMessageContext tokReqMsgCtx, Assertion assertion)
            throws IdentityOAuth2Exception {
        if (issuerNotFoundInAssertion(assertion)) {
            if (log.isDebugEnabled()) {
                log.debug("Issuer is empty in the SAML assertion. Token request for user : " +
                        tokReqMsgCtx.getAuthorizedUser());
            }
            throw new IdentityOAuth2Exception("Issuer is empty in the SAML assertion");
        }
        return true;
    }

    private boolean issuerNotFoundInAssertion(Assertion assertion) {
        return assertion.getIssuer() == null || StringUtils.isEmpty(assertion.getIssuer().getValue());
    }

    /**
     * The Assertion MUST contain a <Subject> element.  The subject MAY identify the resource owner for whom
     * the access token is being requested.  For client authentication, the Subject MUST be the "client_id"
     * of the OAuth client.  When using an Assertion as an authorization grant, the Subject SHOULD identify
     * an authorized accessor for whom the access token is being requested (typically the resource owner, or
     * an authorized delegate).  Additional information identifying the subject/principal of the transaction
     * MAY be included in an <AttributeStatement>.
     * @param tokReqMsgCtx
     * @param assertion
     * @throws IdentityOAuth2Exception
     */
    private boolean validateSubject(OAuthTokenReqMessageContext tokReqMsgCtx, Assertion assertion)
            throws IdentityOAuth2Exception {
        if (assertion.getSubject() != null) {
            validateNameId(tokReqMsgCtx, assertion);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Cannot find a Subject in the Assertion. Token request for the user : " +
                        tokReqMsgCtx.getAuthorizedUser());
            }
            throw new IdentityOAuth2Exception("Cannot find a Subject in the Assertion");
        }
        return true;
    }

    private void validateNameId(OAuthTokenReqMessageContext tokReqMsgCtx, Assertion assertion)
            throws IdentityOAuth2Exception {
        if (StringUtils.isBlank(getNameIdValue(assertion))) {
            if (log.isDebugEnabled()){
                log.debug("NameID in Assertion is not found in subject. Token request for the user : " +
                        tokReqMsgCtx.getAuthorizedUser());
            }
            throw new IdentityOAuth2Exception("NameID in Assertion cannot be empty");
        }
    }

    private String getNameIdValue(Assertion assertion) throws IdentityOAuth2Exception {
        if (assertion.getSubject().getNameID() != null) {
            return assertion.getSubject().getNameID().getValue();
        } else {
            throw new IdentityOAuth2Exception("NameID value is null. Cannot proceed");
        }
    }

    private Assertion getAssertionObject(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {
        try {
            XMLObject samlObject = IdentityUtil.unmarshall(new String(Base64.decodeBase64(
                    tokReqMsgCtx.getOauth2AccessTokenReqDTO().getAssertion())));
            validateAssertionList(samlObject);
            return getAssertion(samlObject);
        } catch (IdentityException e) {
            if(log.isDebugEnabled()){
                log.debug("Error while unmashalling the assertion", e);
            }
            throw new IdentityOAuth2Exception("Error while unmashalling the assertion");
        }
    }

    private Assertion getAssertion(XMLObject samlObject) throws IdentityOAuth2Exception {
        if (samlObject instanceof Assertion) {
            return  (Assertion) samlObject;
        } else {
            throw new IdentityOAuth2Exception("Only Assertion objects are validated in SAML2Bearer Grant Type");
        }
    }

    private boolean validateAssertionList(XMLObject samlObject) throws IdentityOAuth2Exception {
        NodeList assertionList = samlObject.getDOM().getElementsByTagNameNS(SAMLConstants.SAML20_NS, ASSERTION_ELEMENT);
        // Validating for multiple assertions
        if (assertionList.getLength() > 0) {
            throw new IdentityOAuth2Exception("Nested assertions found in request");
        }
        return true;
    }

    private String getTenantDomain(OAuthTokenReqMessageContext tokReqMsgCtx) {
        String tenantDomain = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getTenantDomain();
        if (StringUtils.isEmpty(tenantDomain)) {
            tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        }
        return tenantDomain;
    }

    /**
     * Set the user identified from subject identifier from assertion
     * @param tokReqMsgCtx Token Request Message Context
     * @param identityProvider Identity Provider
     * @param assertion Assertion
     * @param spTenantDomain Service Provider Tenant Domain.
     * @throws IdentityOAuth2Exception
     */
    protected void setUserInMessageContext(OAuthTokenReqMessageContext tokReqMsgCtx, IdentityProvider identityProvider, Assertion
            assertion, String spTenantDomain) throws IdentityOAuth2Exception {
        if (OAuthConstants.UserType.FEDERATED_USER_DOMAIN_PREFIX.equalsIgnoreCase(OAuthServerConfiguration.getInstance()
                .getSaml2BearerTokenUserType())) {
            setFederatedUser(tokReqMsgCtx, assertion, spTenantDomain);
        } else if (OAuthConstants.UserType.LOCAL_USER_TYPE.equalsIgnoreCase(OAuthServerConfiguration.getInstance()
                .getSaml2BearerTokenUserType())) {
            try {
                setLocalUser(tokReqMsgCtx, assertion, spTenantDomain);
            } catch (UserStoreException e) {
                throw new IdentityOAuth2Exception("Error while building local user from given assertion", e);
            }
        } else if (OAuthConstants.UserType.LEGACY_USER_TYPE
                .equalsIgnoreCase(OAuthServerConfiguration.getInstance().getSaml2BearerTokenUserType())) {
            createLegacyUser(tokReqMsgCtx, assertion);
        } else {
            if (isResidentIdp(identityProvider)) {
                try {
                    setLocalUser(tokReqMsgCtx, assertion, spTenantDomain);
                } catch (UserStoreException e) {
                    throw new IdentityOAuth2Exception("Error while building local user from given assertion", e);
                }
            } else {
                setFederatedUser(tokReqMsgCtx, assertion, spTenantDomain);
            }
        }
    }

    /**
     * Build and set Federated User Object.
     * @param tokReqMsgCtx Token request message context.
     * @param assertion SAML2 Assertion.
     * @param tenantDomain Tenant Domain.
     */
    protected void setFederatedUser(OAuthTokenReqMessageContext tokReqMsgCtx, Assertion assertion, String
            tenantDomain) throws IdentityOAuth2Exception {

        String subjectIdentifier = getNameIdValue(assertion);
        if (log.isDebugEnabled()) {
            log.debug("Setting federated user : " + subjectIdentifier + ". with SP tenant domain : " + tenantDomain);
        }
        AuthenticatedUser user =
                AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(subjectIdentifier);
        user.setUserName(subjectIdentifier);
        tokReqMsgCtx.setAuthorizedUser(user);
    }

    /**
     * Set the local user to the token req message context after validating the user.
     *
     * @param tokReqMsgCtx Token Request Message Context
     * @param assertion SAML2 Assertion
     * @param spTenantDomain Service Provider tenant domain
     * @throws UserStoreException
     * @throws IdentityOAuth2Exception
     */
    protected void setLocalUser(OAuthTokenReqMessageContext tokReqMsgCtx, Assertion assertion, String spTenantDomain)
            throws UserStoreException, IdentityOAuth2Exception {

        RealmService realmService = OAuthComponentServiceHolder.getInstance().getRealmService();
        UserStoreManager userStoreManager = null;
        ServiceProvider serviceProvider = null;

        try {
            if (log.isDebugEnabled()) {
                log.debug("Retrieving service provider for client id : " + tokReqMsgCtx.getOauth2AccessTokenReqDTO()
                        .getClientId() + ". Tenant domain : " + spTenantDomain);
            }
            serviceProvider = OAuth2ServiceComponentHolder.getApplicationMgtService().getServiceProviderByClientId(
                    tokReqMsgCtx.getOauth2AccessTokenReqDTO().getClientId(), OAuthConstants.Scope.OAUTH2,
                    spTenantDomain);
        } catch (IdentityApplicationManagementException e) {
            throw new IdentityOAuth2Exception("Error while retrieving service provider for client id : " +
                    tokReqMsgCtx.getOauth2AccessTokenReqDTO().getClientId() + " in tenant domain " + spTenantDomain);
        }

        AuthenticatedUser authenticatedUser = buildLocalUser(tokReqMsgCtx, assertion, serviceProvider, spTenantDomain);
        if (log.isDebugEnabled()) {
            log.debug("Setting local user with username :" + authenticatedUser.getUserName() + ". User store domain :" +
                    authenticatedUser.getUserStoreDomain() + ". Tenant domain : " + authenticatedUser.getTenantDomain
                    () + " . Authenticated subjectIdentifier : " + authenticatedUser
                    .getAuthenticatedSubjectIdentifier());
        }

        if (!spTenantDomain.equalsIgnoreCase(authenticatedUser.getTenantDomain()) && !serviceProvider.isSaasApp()) {
            throw new IdentityOAuth2Exception("Non SaaS app tries to issue token for a different tenant domain. User " +
                    "tenant domain : " + authenticatedUser.getTenantDomain() + ". SP tenant domain : " +
                    spTenantDomain);
        }

        userStoreManager = realmService.getTenantUserRealm(IdentityTenantUtil.getTenantId(authenticatedUser
                .getTenantDomain())).getUserStoreManager();

        if (log.isDebugEnabled()) {
            log.debug("Checking whether the user exists in local user store");
        }
        if (userDoesNotExist(userStoreManager, authenticatedUser)) {
            if (log.isDebugEnabled()) {
                log.debug("User " + authenticatedUser.getUsernameAsSubjectIdentifier(true,false) +
                        " doesn't exist in local user store.");
            }
            throw new IdentityOAuth2Exception("User not found in local user store");
        }
        tokReqMsgCtx.setAuthorizedUser(authenticatedUser);
    }

    private boolean userDoesNotExist(UserStoreManager userStoreManager, AuthenticatedUser authenticatedUser) throws UserStoreException {
        return !userStoreManager.isExistingUser(authenticatedUser.getUsernameAsSubjectIdentifier(true, false));
    }

    /**
     * Build the local user using subject information in the assertion.
     *
     * @param tokReqMsgCtx   Token message context.
     * @param assertion      SAML2 Assertion
     * @param spTenantDomain Service provider tenant domain
     * @return Authenticated User
     */
    protected AuthenticatedUser buildLocalUser(OAuthTokenReqMessageContext tokReqMsgCtx, Assertion assertion,
                                               ServiceProvider serviceProvider, String spTenantDomain)
            throws IdentityOAuth2Exception {

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        String subjectIdentifier = getNameIdValue(assertion);
        String userTenantDomain = null;
        if (log.isDebugEnabled()) {
            log.debug("Building local user with assertion subject : " + subjectIdentifier);
        }
        authenticatedUser.setUserStoreDomain(UserCoreUtil.extractDomainFromName(subjectIdentifier));
        authenticatedUser.setUserName(MultitenantUtils.getTenantAwareUsername(UserCoreUtil.removeDomainFromName
                (subjectIdentifier)));

        userTenantDomain = MultitenantUtils.getTenantDomain(subjectIdentifier);
        if (StringUtils.isEmpty(userTenantDomain)) {
            userTenantDomain = spTenantDomain;
        }

        authenticatedUser.setTenantDomain(userTenantDomain);
        authenticatedUser.setAuthenticatedSubjectIdentifier(authenticatedUser.getUserName(), serviceProvider);
        return authenticatedUser;
    }

    /**
     * This method is setting the username removing the domain name without checking whether the user is federated
     * or not. This fix has done for support backward capability.
     *
     * @param tokReqMsgCtx Token request message context.
     * @param assertion    SAML2 Assertion.
     */
    protected void createLegacyUser(OAuthTokenReqMessageContext tokReqMsgCtx, Assertion assertion)
            throws IdentityOAuth2Exception {
        //Check whether NameID value is null before call this method.
        String resourceOwnerUserName = getNameIdValue(assertion);
        AuthenticatedUser user = OAuth2Util.getUserFromUserName(resourceOwnerUserName);

        user.setAuthenticatedSubjectIdentifier(resourceOwnerUserName);
        user.setFederatedUser(true);
        tokReqMsgCtx.setAuthorizedUser(user);
    }

}
