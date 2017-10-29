/*
 * Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml1.core.Assertion;
import org.opensaml.saml1.core.Audience;
import org.opensaml.saml1.core.AudienceRestrictionCondition;
import org.opensaml.saml1.core.AuthenticationStatement;
import org.opensaml.saml1.core.Conditions;
import org.opensaml.saml1.core.ConfirmationMethod;
import org.opensaml.saml1.core.Subject;
import org.opensaml.saml1.core.SubjectConfirmation;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.validation.ValidationException;
import org.w3c.dom.NodeList;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AbstractAuthorizationGrantHandler;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.util.X509CredentialImpl;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;

/**
 * This implements SAML 1.0 Bearer Assertion Profile(this is to be documented) for OAuth 2.0
 */
public class SAML1BearerGrantHandler extends AbstractAuthorizationGrantHandler {

    private static Log log = LogFactory.getLog(SAML1BearerGrantHandler.class);

    SAMLSignatureProfileValidator profileValidator = null;
    private boolean audienceRestrictionValidationEnabled = false;
    private static final String SAML10_BEARER_GRANT_TYPE_CONFIG_FILE = "SAML10_BearerGrantType.properties";

    public void init() throws IdentityOAuth2Exception {

        super.init();

        Thread thread = Thread.currentThread();
        ClassLoader loader = thread.getContextClassLoader();
        thread.setContextClassLoader(this.getClass().getClassLoader());

        try {
            DefaultBootstrap.bootstrap();
        } catch (ConfigurationException e) {
            String errorMessage = "Error in bootstrapping the OpenSAML library";
            log.error(errorMessage, e);
            throw new IdentityOAuth2Exception(errorMessage, e);
        } finally {
            thread.setContextClassLoader(loader);
        }

        profileValidator = new SAMLSignatureProfileValidator();

        Properties grantTypeProperties = new Properties();
        InputStream stream = loader.getResourceAsStream("repository/conf/" + SAML10_BEARER_GRANT_TYPE_CONFIG_FILE);
        if (stream != null) {
            try {
                grantTypeProperties.load(stream);
                audienceRestrictionValidationEnabled =
                        Boolean.parseBoolean(grantTypeProperties.getProperty("audienceRestrictionValidationEnabled"));
                if (log.isDebugEnabled()) {
                    log.debug("Audience restriction validation enabled is set to " +
                            audienceRestrictionValidationEnabled);
                }
            } catch (IOException e) {
                log.warn(
                      "Failed to load the SAML-1.0-BearerGrantType.properties stream. The default configurations are " +
                        "used instead of configurations defined in " + SAML10_BEARER_GRANT_TYPE_CONFIG_FILE + " file.");
            } finally {
                try {
                    stream.close();
                } catch (IOException e) {
                    log.warn("Failed to close the input stream of " + SAML10_BEARER_GRANT_TYPE_CONFIG_FILE, e);
                }
            }

        }
    }

    /**
     * We're validating the SAML token that we receive from the request. Through the assertion parameter is the POST
     * request. A request format that we handle here looks like,
     * <p/>
     * POST /token.oauth2 HTTP/1.1
     * Host: as.example.com
     * Content-Type: application/x-www-form-urlencoded
     * <p/>
     * grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Asaml1-bearer&
     * assertion=PHNhbWxwOl...[omitted for brevity]...ZT4
     *
     * @param tokReqMsgCtx Token message request context
     * @return true if validation is successful, false otherwise
     * @throws org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception
     */
    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {
        boolean validGrant = super.validateGrant(tokReqMsgCtx);

        Assertion assertion;
        IdentityProvider identityProvider = null;
        String tokenEndpointAlias = null;
        String tenantDomain = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getTenantDomain();
        if (tenantDomain == null || "".equals(tenantDomain)) {
            tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        }

        RequestParameter[] requestParameters = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getRequestParameters();
        for (RequestParameter requestParameter : requestParameters) {
            if (requestParameter.getKey().equals("assertion")) {
                String[] values = requestParameter.getValue();
                tokReqMsgCtx.getOauth2AccessTokenReqDTO().setAssertion(values[0]);
                break;
            }
        }

        if (log.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.SAML_ASSERTION)) {
            log.debug("Received SAML assertion : " +
                      new String(Base64.decodeBase64(tokReqMsgCtx.getOauth2AccessTokenReqDTO().getAssertion()), StandardCharsets.UTF_8));
        }

        try {
            XMLObject samlObject = IdentityUtil.unmarshall(new String(Base64.decodeBase64(
                    tokReqMsgCtx.getOauth2AccessTokenReqDTO().getAssertion())));
            // Validating for multiple assertions
            NodeList assertionList = samlObject.getDOM().getElementsByTagNameNS(SAMLConstants.SAML1_NS, "Assertion");
            if (assertionList.getLength() > 0) {
                log.error("Invalid schema for SAML Assertion. Nested assertions detected.");
                return false;
            }

            if (samlObject instanceof Assertion) {
                assertion = (Assertion) samlObject;
            } else {
                log.error("Only Assertion objects are validated in SAML1Bearer Grant Type");
                return false;
            }
        } catch (IdentityException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error occurred while unmarshalling SAML1.0 assertion", e);
            }
            return false;
        }

        /**
         * The Assertion MUST contain a <Subject> element.  The subject MAY identify the resource owner for whom
         * the access token is being requested.  For client authentication, the Subject MUST be the "client_id"
         * of the OAuth client.  When using an Assertion as an authorization grant, the Subject SHOULD identify
         * an authorized accessor for whom the access token is being requested (typically the resource owner, or
         * an authorized delegate).  Additional information identifying the subject/principal of the transaction
         * MAY be included in an <AttributeStatement>.
         */

        List<AuthenticationStatement> authenticationStatements = assertion.getAuthenticationStatements();
        Subject subject;
        if (authenticationStatements != null && authenticationStatements.size() > 0) {
            AuthenticationStatement authenticationStatement = authenticationStatements.get(0);
            subject = authenticationStatement.getSubject();
            if (subject != null) {
                String resourceOwnerUserName = subject.getNameIdentifier().getNameIdentifier();
                if (resourceOwnerUserName == null || resourceOwnerUserName.equals("")) {
                    if (log.isDebugEnabled()) {
                        log.debug("NameID in Assertion cannot be empty");
                    }
                    return false;
                }
                AuthenticatedUser user = OAuth2Util.getUserFromUserName(resourceOwnerUserName);
                user.setAuthenticatedSubjectIdentifier(resourceOwnerUserName);
                user.setFederatedUser(true);
                tokReqMsgCtx.setAuthorizedUser(user);
                if (log.isDebugEnabled()) {
                    log.debug("Resource Owner User Name is set to " + resourceOwnerUserName);
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Subject element cannot be empty.");
                }
                return false;
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Authentication Statement cannot be empty");
            }
            return false;
        }

        if (assertion.getIssuer() == null || assertion.getIssuer().isEmpty()) {
            if (log.isDebugEnabled()) {
                log.debug("Issuer is empty in the SAML assertion");
            }
            return false;
        } else {
            try {
                if (log.isDebugEnabled()) {
                    log.debug("Issuer is :" + assertion.getIssuer());
                }
                identityProvider =
                        IdentityProviderManager.getInstance().getIdPByAuthenticatorPropertyValue("IdPEntityId",
                                                                                                 assertion.getIssuer(),
                                                                                                 tenantDomain, false);
                // IF Federated IDP not found get the resident IDP and check,
                // resident IDP entitiID == issuer
                if (identityProvider != null) {
                    if (IdentityApplicationConstants.RESIDENT_IDP_RESERVED_NAME
                            .equals(identityProvider.getIdentityProviderName())) {
                        identityProvider = IdentityProviderManager.getInstance().getResidentIdP(tenantDomain);

                        FederatedAuthenticatorConfig[] fedAuthnConfigs =
                                identityProvider.getFederatedAuthenticatorConfigs();
                        String idpEntityId = null;

                        // Get SAML authenticator
                        FederatedAuthenticatorConfig samlAuthenticatorConfig =
                                IdentityApplicationManagementUtil.getFederatedAuthenticator(fedAuthnConfigs,
                                                              IdentityApplicationConstants.Authenticator.SAML2SSO.NAME);
                        // Get Entity ID from SAML authenticator
                        Property samlProperty =
                                IdentityApplicationManagementUtil.getProperty(samlAuthenticatorConfig.getProperties(),
                                                     IdentityApplicationConstants.Authenticator.SAML2SSO.IDP_ENTITY_ID);
                        if (samlProperty != null) {
                            idpEntityId = samlProperty.getValue();
                        }

                        if (idpEntityId == null || !assertion.getIssuer().equals(idpEntityId)) {
                            if (log.isDebugEnabled()) {
                                log.debug("SAML Token Issuer verification failed or Issuer not registered");
                            }
                            return false;
                        }

                        // Get OpenIDConnect authenticator == OAuth
                        // authenticator
                        FederatedAuthenticatorConfig oauthAuthenticatorConfig =
                                IdentityApplicationManagementUtil.getFederatedAuthenticator(fedAuthnConfigs,
                                                                  IdentityApplicationConstants.Authenticator.OIDC.NAME);
                        // Get OAuth token endpoint
                        Property oauthProperty =
                                IdentityApplicationManagementUtil.getProperty(oauthAuthenticatorConfig.getProperties(),
                                                      IdentityApplicationConstants.Authenticator.OIDC.OAUTH2_TOKEN_URL);
                        if (oauthProperty != null) {
                            tokenEndpointAlias = oauthProperty.getValue();
                        }
                    } else {
                        // Get Alias from Federated IDP
                        tokenEndpointAlias = identityProvider.getAlias();
                    }
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("SAML Token Issuer verification failed or Issuer not registered");
                    }
                    return false;
                }
            } catch (IdentityProviderManagementException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Error while getting Federated Identity Provider ", e);
                }
            }
        }

        /**
         * The Assertion MUST contain <Conditions> element with an <AudienceRestriction> element with an <Audience>
         * element containing a URI reference that identifies the authorization server, or the service provider
         * SAML entity of its controlling domain, as an intended audience.  The token endpoint URL of the
         * authorization server MAY be used as an acceptable value for an <Audience> element.  The authorization
         * server MUST verify that it is an intended audience for the Assertion.
         *
         * In some cases, adding multiple audiences are not allowed by token providers. As a result, audience restriction
         * validation is set to false by default. To enable audience restriction, you need to place a properties file at
         * repository/conf/SAML-1.0-BearerGrantType.properties witch content audienceRestrictionValidationEnabled = true
         */

        if (audienceRestrictionValidationEnabled) {
            if (tokenEndpointAlias == null || tokenEndpointAlias.equals("")) {
                String errorMsg = "Token Endpoint alias of the local Identity Provider has not been " +
                                  "configured for " + identityProvider.getIdentityProviderName();
                if (log.isDebugEnabled()) {
                    log.debug(errorMsg);
                }
                return false;
            }

            Conditions conditions = assertion.getConditions();
            if (conditions != null) {
                List<AudienceRestrictionCondition> audienceRestrictions = conditions.getAudienceRestrictionConditions();
                if (audienceRestrictions != null && !audienceRestrictions.isEmpty()) {
                    boolean audienceFound = false;
                    for (AudienceRestrictionCondition audienceRestriction : audienceRestrictions) {
                        if (audienceRestriction.getAudiences() != null &&
                            audienceRestriction.getAudiences().size() > 0) {
                            for (Audience audience : audienceRestriction.getAudiences()) {
                                if (audience.getUri().equals(tokenEndpointAlias)) {
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
                            log.debug("SAML Assertion Audience Restriction validation failed");
                        }
                        return false;
                    }
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("SAML Assertion doesn't contain AudienceRestrictions");
                    }
                    return false;
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("SAML Assertion doesn't contain Conditions");
                }
                return false;
            }
        }

        /**
         * The Assertion MUST have an expiry that limits the time window during which it can be used.  The expiry
         * can be expressed either as the NotOnOrAfter attribute of the <Conditions> element or as the NotOnOrAfter
         * attribute of a suitable <SubjectConfirmationData> element.
         */

        /**
         * The <Subject> element MUST contain at least one <SubjectConfirmation> element that allows the
         * authorization server to confirm it as a Bearer Assertion.  Such a <SubjectConfirmation> element MUST
         * have a Method attribute with a value of "urn:oasis:names:tc:SAML:1.0:cm:bearer".  The
         * <SubjectConfirmation> element MUST contain a <SubjectConfirmationData> element, unless the Assertion
         * has a suitable NotOnOrAfter attribute on the <Conditions> element, in which case the
         * <SubjectConfirmationData> element MAY be omitted.
         * The <SubjectConfirmationData> element MUST have a NotOnOrAfter attribute that limits the window during
         * which the Assertion can be confirmed.  The <SubjectConfirmationData> element MAY also contain an Address
         * attribute limiting the client address from which the Assertion can be delivered.  Verification of the
         * Address is at the discretion of the authorization server.
         */

        DateTime notOnOrAfterFromConditions = null;
        Set<DateTime> notOnOrAfterFromSubjectConfirmations = new HashSet<DateTime>();
        boolean bearerFound = false;

        if (assertion.getConditions() != null && assertion.getConditions().getNotOnOrAfter() != null) {
            notOnOrAfterFromConditions = assertion.getConditions().getNotOnOrAfter();
        }

        SubjectConfirmation subjectConfirmation = subject.getSubjectConfirmation();
        List<ConfirmationMethod> confirmationMethods = subjectConfirmation.getConfirmationMethods();
        for (ConfirmationMethod confirmationMethod : confirmationMethods) {
            if (OAuthConstants.OAUTH_SAML1_BEARER_METHOD.equals(confirmationMethod.getConfirmationMethod())) {
                bearerFound = true;
            }

        }
        if (!bearerFound) {
            if (log.isDebugEnabled()) {
                log.debug("Cannot find Method attribute in SubjectConfirmation " + subject.getSubjectConfirmation());
            }
            return false;
        }

        XMLObject confirmationData = subject.getSubjectConfirmation().getSubjectConfirmationData();
        if (confirmationData == null) {
            log.warn("Subject confirmation data is missing.");
        }

        if (!bearerFound) {
            if (log.isDebugEnabled()) {
                log.debug("Failed to find a SubjectConfirmation with a Method attribute having : " +
                          OAuthConstants.OAUTH_SAML1_BEARER_METHOD);
            }
            return false;
        }

        /**
         * The authorization server MUST verify that the NotOnOrAfter instant has not passed, subject to allowable
         * clock skew between systems.  An invalid NotOnOrAfter instant on the <Conditions> element invalidates
         * the entire Assertion.  An invalid NotOnOrAfter instant on a <SubjectConfirmationData> element only
         * invalidates the individual <SubjectConfirmation>.  The authorization server MAY reject Assertions with
         * a NotOnOrAfter instant that is unreasonably far in the future.  The authorization server MAY ensure
         * that Bearer Assertions are not replayed, by maintaining the set of used ID values for the length of
         * time for which the Assertion would be considered valid based on the applicable NotOnOrAfter instant.
         */
        long timestampSkewInMillis = OAuthServerConfiguration.getInstance().getTimeStampSkewInSeconds() * 1000;
        if (notOnOrAfterFromConditions != null && notOnOrAfterFromConditions.plus(timestampSkewInMillis).isBeforeNow
                ()) {
            // notOnOrAfter is an expired timestamp
            if (log.isDebugEnabled()) {
                log.debug("NotOnOrAfter is having an expired timestamp in Conditions element");
            }
            return false;
        }
        boolean validSubjectConfirmationDataExists = false;
        if (!notOnOrAfterFromSubjectConfirmations.isEmpty()) {
            for (DateTime entry : notOnOrAfterFromSubjectConfirmations) {
                if (entry.plus(timestampSkewInMillis).isAfterNow()) {
                    validSubjectConfirmationDataExists = true;
                }
            }
        }
        if (notOnOrAfterFromConditions == null && !validSubjectConfirmationDataExists) {
            if (log.isDebugEnabled()) {
                log.debug("No valid NotOnOrAfter element found in SubjectConfirmations");
            }
            return false;
        }

        /**
         * The Assertion MUST be digitally signed by the issuer and the authorization server MUST verify the
         * signature.
         */

        try {
            profileValidator.validate(assertion.getSignature());
        } catch (ValidationException e) {
            // Indicates signature did not conform to SAML1.0 Signature profile
            if(log.isDebugEnabled()) {
                log.debug("Signature did not conform to SAML1.0 Signature profile", e);
            }
            return false;
        }

        X509Certificate x509Certificate = null;
        try {
            x509Certificate = (X509Certificate) IdentityApplicationManagementUtil
                    .decodeCertificate(identityProvider.getCertificate());
        } catch (CertificateException e) {
            String message = "Error occurred while decoding public certificate of Identity Provider "
                    + identityProvider.getIdentityProviderName() + " for tenant domain " + tenantDomain;
            throw new IdentityOAuth2Exception(message, e);
        }

        try {
            X509Credential x509Credential = new X509CredentialImpl(x509Certificate);
            SignatureValidator signatureValidator = new SignatureValidator(x509Credential);
            signatureValidator.validate(assertion.getSignature());
            if(log.isDebugEnabled()) {
                log.debug("Signature validation successful");
            }
        } catch (ValidationException e) {
            if (log.isDebugEnabled()) {
                log.debug("Signature validation failure:" + e.getMessage(), e);
            }
            return false;
        }

        tokReqMsgCtx.setScope(tokReqMsgCtx.getOauth2AccessTokenReqDTO().getScope());

        // Storing the Assertion. This will be used in OpenID Connect for example
        tokReqMsgCtx.addProperty(OAuthConstants.OAUTH_SAML2_ASSERTION, assertion);

        // Invoking extension
        SAML2TokenCallbackHandler callback =
                OAuthServerConfiguration.getInstance()
                                        .getSAML2TokenCallbackHandler();
        if (callback != null) {
            if (log.isDebugEnabled()) {
                log.debug("Invoking the SAML2 Token callback handler");
            }
            callback.handleSAML2Token(tokReqMsgCtx);
        }

        return validGrant;
    }

    @Override
    public boolean validateScope(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {
        return true;
    }

    @Override
    public boolean authorizeAccessDelegation(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {
        return true;
    }

    @Override
    public boolean issueRefreshToken() throws IdentityOAuth2Exception {

        return OAuthServerConfiguration.getInstance()
                .getValueForIsRefreshTokenAllowed(OAuthConstants.OAUTH_SAML1_BEARER_METHOD);
    }
}
