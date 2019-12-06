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
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Audience;
import org.opensaml.saml.saml2.core.AudienceRestriction;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.security.x509.X509Credential;
import org.opensaml.xmlsec.signature.support.SignatureValidationProvider;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.w3c.dom.NodeList;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.context.RegistryType;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.PermissionsAndRoleConfig;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.RoleMapping;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.core.persistence.IdentityPersistenceManager;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AbstractAuthorizationGrantHandler;
import org.wso2.carbon.identity.oauth2.util.ClaimsUtil;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.util.X509CredentialImpl;
import org.wso2.carbon.identity.saml.common.util.SAMLInitializer;
import org.wso2.carbon.identity.saml.common.util.UnmarshallUtils;
import org.wso2.carbon.identity.saml.common.util.exception.IdentityUnmarshallingException;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.registry.core.Registry;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * This implements SAML 2.0 Bearer Assertion Profile for OAuth 2.0 -
 * http://tools.ietf.org/html/draft-ietf-oauth-saml2-bearer-14.
 */
public class SAML2BearerGrantHandler extends AbstractAuthorizationGrantHandler {

    public static final String ASSERTION_ELEMENT = "Assertion";
    public static final String IDP_ENTITY_ID = "IdPEntityId";
    private static final Log log = LogFactory.getLog(SAML2BearerGrantHandler.class);
    private static final String SAMLSSO_AUTHENTICATOR = "samlsso";
    private static final String SAML2SSO_AUTHENTICATOR_NAME = "SAMLSSOAuthenticator";

    public static final String SECURITY_SAML_SIGN_KEY_STORE_LOCATION = "Security.SAMLSignKeyStore.Location";
    public static final String SECURITY_SAML_SIGN_KEY_STORE_TYPE = "Security.SAMLSignKeyStore.Type";
    public static final String SECURITY_SAML_SIGN_KEY_STORE_PASSWORD = "Security.SAMLSignKeyStore.Password";
    public static final String SECURITY_SAML_SIGN_KEY_STORE_KEY_ALIAS = "Security.SAMLSignKeyStore.KeyAlias";
    public static final String SECURITY_SAML_SIGN_KEY_STORE_KEY_PASSWORD = "Security.SAMLSignKeyStore.KeyPassword";

    SAMLSignatureProfileValidator profileValidator = null;

    @Override
    public void init() throws IdentityOAuth2Exception {

        super.init();

        Thread thread = Thread.currentThread();
        ClassLoader originalClassLoader = thread.getContextClassLoader();
        thread.setContextClassLoader(this.getClass().getClassLoader());

        try {
            SAMLInitializer.doBootstrap();
        } catch (InitializationException e) {
            log.error("Error in bootstrapping the OpenSAML3 library", e);
            throw new IdentityOAuth2Exception("Error in bootstrapping the OpenSAML3 library");
        } finally {
            thread.setContextClassLoader(originalClassLoader);
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
        // If SAMLSignKeyStore property defined in the carbon.xml then validate the signature against provided
        // SAML Sign KeyStore certificate else validate against the IDP certificate.
        if (isSAMLSignKeyStoreConfigured()) {
            validateSignatureAgainstSAMLSignKeyStoreCertificate(assertion);
        } else {
            validateSignatureAgainstIdpCertificate(assertion, tenantDomain, identityProvider);
        }
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

    @Override
    public OAuth2AccessTokenRespDTO issue(OAuthTokenReqMessageContext tokenReqMsgCtx) throws IdentityOAuth2Exception {
        OAuth2AccessTokenRespDTO responseDTO = super.issue(tokenReqMsgCtx);

        String[] scope = tokenReqMsgCtx.getScope();
        if (OAuth2Util.isOIDCAuthzRequest(scope)) {
            Assertion assertion = (Assertion) tokenReqMsgCtx.getProperty(OAuthConstants.OAUTH_SAML2_ASSERTION);

            if (assertion != null) {
                handleClaimsInAssertion(tokenReqMsgCtx, responseDTO, assertion);
            }
        }

        return responseDTO;
    }

    protected void handleClaimsInAssertion(OAuthTokenReqMessageContext tokenReqMsgCtx, OAuth2AccessTokenRespDTO
            responseDTO, Assertion assertion) throws IdentityOAuth2Exception {

        Map<String, String> attributes = ClaimsUtil.extractClaimsFromAssertion(
                tokenReqMsgCtx, responseDTO, assertion, FrameworkUtils.getMultiAttributeSeparator());
        if (attributes != null && attributes.size() > 0) {

            String tenantDomain = tokenReqMsgCtx.getOauth2AccessTokenReqDTO().getTenantDomain();
            if (StringUtils.isBlank(tenantDomain)) {
                tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
            }

            if (OAuthServerConfiguration.getInstance().isConvertOriginalClaimsFromAssertionsToOIDCDialect()) {

                IdentityProvider identityProvider = getIdentityProvider(assertion, tenantDomain);

                boolean localClaimDialect = identityProvider.getClaimConfig().isLocalClaimDialect();
                ClaimMapping[] idPClaimMappings = identityProvider.getClaimConfig().getClaimMappings();
                Map<String, String> localClaims;

                if (ClaimsUtil.isResidentIdp(identityProvider)) {
                    localClaims = handleClaimsForResidentIDP(attributes, identityProvider);
                } else {
                    localClaims = handleClaimsForIDP(attributes, tenantDomain, identityProvider,
                            localClaimDialect, idPClaimMappings);
                }

                // Handle IdP Role Mappings
                if (localClaims != null && StringUtils
                        .isNotBlank(localClaims.get(FrameworkConstants.LOCAL_ROLE_CLAIM_URI))) {

                    String updatedRoleClaimValue = getUpdatedRoleClaimValue(identityProvider,
                            localClaims.get(FrameworkConstants.LOCAL_ROLE_CLAIM_URI));
                    if (updatedRoleClaimValue != null) {
                        localClaims.put(FrameworkConstants.LOCAL_ROLE_CLAIM_URI, updatedRoleClaimValue);
                    } else {
                        localClaims.remove(FrameworkConstants.LOCAL_ROLE_CLAIM_URI);
                        if (localClaims.isEmpty()) {
                            // This is added to handle situation where removing all role mappings and requesting
                            // the id token using same SAML assertion.
                            addUserAttributesToCache(responseDTO, tokenReqMsgCtx,
                                    new HashMap<ClaimMapping, String>());
                        }
                    }
                }

                // ########################### all claims are in local dialect ############################

                if (localClaims != null && localClaims.size() > 0) {
                    Map<String, String> oidcClaims;
                    try {
                        oidcClaims = ClaimsUtil.convertClaimsToOIDCDialect(tokenReqMsgCtx,
                                localClaims);
                    } catch (IdentityApplicationManagementException | IdentityException e) {
                        throw new IdentityOAuth2Exception(
                                "Error while converting user claims to OIDC dialect from idp " + identityProvider
                                        .getIdentityProviderName(), e);
                    }
                    Map<ClaimMapping, String> claimMappings = FrameworkUtils.buildClaimMappings(oidcClaims);
                    addUserAttributesToCache(responseDTO, tokenReqMsgCtx, claimMappings);
                }
            } else {
                // Not converting claims. Sending the claim uris in original format.
                Map<ClaimMapping, String> claimMappings = FrameworkUtils.buildClaimMappings(attributes);
                // Handle IdP Role Mappings
                for (Iterator<Map.Entry<ClaimMapping, String>> iterator = claimMappings.entrySet()
                        .iterator(); iterator.hasNext(); ) {

                    Map.Entry<ClaimMapping, String> entry = iterator.next();
                    if (FrameworkConstants.LOCAL_ROLE_CLAIM_URI
                            .equals(entry.getKey().getLocalClaim().getClaimUri()) && StringUtils
                            .isNotBlank(entry.getValue())) {

                        IdentityProvider identityProvider = getIdentityProvider(assertion, tenantDomain);
                        String updatedRoleClaimValue = getUpdatedRoleClaimValue(identityProvider,
                                entry.getValue());
                        if (updatedRoleClaimValue != null) {
                            entry.setValue(updatedRoleClaimValue);
                        } else {
                            iterator.remove();
                        }
                        break;
                    }
                }
                addUserAttributesToCache(responseDTO, tokenReqMsgCtx, claimMappings);
            }
        }
    }

    /**
     * This method will update the role claim value received from the IdP using the defined role claim configuration
     * for the IdP.
     * Also, if "ReturnOnlyMappedLocalRoles" configuration is enabled, then server will only return the mapped role
     * values.
     *
     * @param identityProvider      identity provider
     * @param currentRoleClaimValue current role claim value.
     * @return updated role claim string
     */
    private String getUpdatedRoleClaimValue(IdentityProvider identityProvider, String currentRoleClaimValue) {

        if (StringUtils.equalsIgnoreCase(IdentityApplicationConstants.RESIDENT_IDP_RESERVED_NAME, identityProvider
                .getIdentityProviderName())) {
            return currentRoleClaimValue;
        }

        PermissionsAndRoleConfig permissionAndRoleConfig = identityProvider.getPermissionAndRoleConfig();
        if (permissionAndRoleConfig != null && ArrayUtils.isNotEmpty(permissionAndRoleConfig.getRoleMappings())) {

            String[] receivedRoles = currentRoleClaimValue.split(FrameworkUtils.getMultiAttributeSeparator());
            List<String> updatedRoleClaimValues = new ArrayList<>();
            loop:
            for (String receivedRole : receivedRoles) {
                for (RoleMapping roleMapping : permissionAndRoleConfig.getRoleMappings()) {
                    if (roleMapping.getRemoteRole().equals(receivedRole)) {
                        updatedRoleClaimValues.add(roleMapping.getLocalRole().getLocalRoleName());
                        continue loop;
                    }
                }
                if (!OAuthServerConfiguration.getInstance().isReturnOnlyMappedLocalRoles()) {
                    updatedRoleClaimValues.add(receivedRole);
                }
            }
            if (!updatedRoleClaimValues.isEmpty()) {
                return StringUtils.join(updatedRoleClaimValues, FrameworkUtils.getMultiAttributeSeparator());
            }
            return null;
        }
        if (!OAuthServerConfiguration.getInstance().isReturnOnlyMappedLocalRoles()) {
            return currentRoleClaimValue;
        }
        return null;
    }

    protected Map<String, String> handleClaimsForIDP(Map<String, String> attributes, String tenantDomain,
                                                     IdentityProvider identityProvider, boolean localClaimDialect,
                                                     ClaimMapping[] idPClaimMappings) {

        return ClaimsUtil
                .handleClaimsForIDP(attributes, tenantDomain, identityProvider, localClaimDialect, idPClaimMappings);
    }

    protected Map<String, String> handleClaimsForResidentIDP(Map<String, String> attributes, IdentityProvider
            identityProvider) {

        return ClaimsUtil.handleClaimsForResidentIDP(attributes, identityProvider);
    }


    protected static void addUserAttributesToCache(OAuth2AccessTokenRespDTO tokenRespDTO, OAuthTokenReqMessageContext
            msgCtx, Map<ClaimMapping, String> userAttributes) {

        ClaimsUtil.addUserAttributesToCache(tokenRespDTO, msgCtx, userAttributes);
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
                recipientURLS.addAll(getRecipientUrls(subjectConfirmation.getSubjectConfirmationData()));
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

            /*
              The process mentioned below is done because OpenSAML3 does not support OSGi refer
              https://shibboleth.1660669.n2.nabble.com/Null-Pointer-Exception-from-UnmarshallerFactory-while-migrating-from-OpenSAML2-x-to-OpenSAML3-x-td7643903.html
              and https://stackoverflow.com/questions/37948303/opensaml3-resource-not-found-default-config-xml-in-osgi-container
            */

            Thread thread = Thread.currentThread();
            ClassLoader originalClassLoader = thread.getContextClassLoader();
            thread.setContextClassLoader(SignatureValidationProvider.class.getClassLoader());

            try {
                SignatureValidator.validate(assertion.getSignature(), x509Credential);
            } finally {
                thread.setContextClassLoader(originalClassLoader);
            }
        } catch (SignatureException e) {
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
        } catch (SignatureException e) {
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
        if (ClaimsUtil.isResidentIdp(identityProvider)) {
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
        //validateIdpEntityId(assertion, tenantDomain,  getIdpEntityId(fedAuthnConfigs));
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

    private IdentityProvider getIdentityProvider(Assertion assertion, String tenantDomain)
            throws IdentityOAuth2Exception {
        try {
            IdentityProvider identityProvider = getIdentityProviderFromManager(assertion, tenantDomain);
            checkNullIdentityProvider(assertion, tenantDomain, identityProvider);
            if (ClaimsUtil.isResidentIdp(identityProvider)) {
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
            throws IdentityProviderManagementException, IdentityOAuth2Exception {
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
        if (identityProvider == null) {
            if (log.isDebugEnabled()) {
                log.debug("SAML Token Issuer : " + assertion.getIssuer().getValue() +
                        " is not registered as a local Identity Provider in tenant : " + tenantDomain +
                        ". Hence checking if the assertion is from resident IdP with IdP Entity ID Alias enabled");
            }
            if (validateIdpEntityIdAliasFromSAMLSP(assertion, tenantDomain)) {
                identityProvider = IdentityProviderManager.getInstance().getResidentIdP(tenantDomain);
            }
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

    /**
     * If the token issuer validation fails against the resident identity provider's IdP Entity ID, checks whether the
     * token issuer has been overriden by an "Idp Entity ID Alias" specified in a SAML SSO configuration. The check
     * is done against IdP Entity ID Alias values of SAML SSO configurations in the registry. The SAML SSO configurations
     * that needs to be checked are identified from the audience restrictions in the SAML assertion as it contains the
     * "issuer" of the SAML SSO configuration with respective to the SAML SP.
     *
     * @param assertion
     * @param tenantDomain
     * @return
     * @throws IdentityOAuth2Exception
     */
    private Boolean validateIdpEntityIdAliasFromSAMLSP(Assertion assertion, String tenantDomain)
            throws IdentityOAuth2Exception {

        Conditions conditions = assertion.getConditions();
        List<AudienceRestriction> audienceRestrictions = conditions.getAudienceRestrictions();
        validateAudienceRestriction(audienceRestrictions);
        for (AudienceRestriction audienceRestriction : audienceRestrictions) {
            if (CollectionUtils.isNotEmpty(audienceRestriction.getAudiences())) {
                for (Audience audience : audienceRestriction.getAudiences()) {
                    SAMLSSOServiceProviderDO samlssoServiceProviderDO = getSAMLSSOServiceProvider
                            (audience.getAudienceURI(), tenantDomain);
                    if (samlssoServiceProviderDO != null) {
                        if (samlssoServiceProviderDO.getIdpEntityIDAlias() != null &&
                                samlssoServiceProviderDO.getIdpEntityIDAlias().equals(assertion.getIssuer().
                                        getValue())) {
                            if (log.isDebugEnabled()) {
                                log.debug("Token Issuer verified against IdP Entity ID Alias : " +
                                        samlssoServiceProviderDO.getIdpEntityIDAlias() + " of SAML Service Provider " +
                                        samlssoServiceProviderDO.getIssuer() + " in tenant : " + tenantDomain + ".");
                            }
                            return true;
                        }
                    }
                }
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("No SAML Service Provider configuration with IdP Entity ID Alias " +
                    "similar to token issuer found.");
        }
        return false;
    }

    private SAMLSSOServiceProviderDO getSAMLSSOServiceProvider(String issuerName, String tenantDomain)
            throws IdentityOAuth2Exception {

        int tenantId;
        RealmService realmService = OAuthComponentServiceHolder.getInstance().getRealmService();

        if (StringUtils.isBlank(tenantDomain)) {
            tenantDomain = org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
            tenantId = org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_ID;
        } else {
            try {
                tenantId = realmService.getTenantManager().getTenantId(tenantDomain);
            } catch (UserStoreException e) {
                throw new IdentityOAuth2Exception("Error occurred while retrieving tenant id for the domain : " +
                        tenantDomain, e);
            }
        }

        try {
            PrivilegedCarbonContext.startTenantFlow();
            PrivilegedCarbonContext privilegedCarbonContext = PrivilegedCarbonContext.getThreadLocalCarbonContext();
            privilegedCarbonContext.setTenantId(tenantId);
            privilegedCarbonContext.setTenantDomain(tenantDomain);

            IdentityTenantUtil.initializeRegistry(tenantId, tenantDomain);
            IdentityPersistenceManager persistenceManager = IdentityPersistenceManager.getPersistanceManager();
            Registry registry = (Registry) PrivilegedCarbonContext.getThreadLocalCarbonContext().getRegistry
                    (RegistryType.SYSTEM_CONFIGURATION);
            return persistenceManager.getServiceProvider(registry, issuerName);
        } catch (IdentityException e) {
            throw new IdentityOAuth2Exception("Error occurred while validating existence of SAML service provider " +
                    "'" + issuerName + "' that issued the assertion in the tenant domain '" + tenantDomain + "'");
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
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

    /**
     * Get the user id of the identity provider.
     *
     * @param tokReqMsgCtx
     * @param identityProvider
     * @param assertion
     * @return
     * @throws IdentityOAuth2Exception
     */
    protected String getUserId(OAuthTokenReqMessageContext tokReqMsgCtx, IdentityProvider identityProvider,
                             Assertion assertion) throws IdentityOAuth2Exception {

        // Check whether the user id from claims is enabled for the SAML bearer grant.
        if (OAuthServerConfiguration.getInstance().getSaml2UserIdFromClaims()) {

            // If the "user id found among claims" option enabled for the SAML federated identity provider then get the
            // user id, from the claims sent through the assertion.
            if (isUserIdFromClaimsEnabled(identityProvider)) {
                Map<String, String> attributes = ClaimsUtil.extractClaimsFromAssertion(tokReqMsgCtx, null, assertion,
                        FrameworkUtils.getMultiAttributeSeparator());
                String userClaimURI = identityProvider.getClaimConfig().getUserClaimURI();
                if (StringUtils.isNotBlank(userClaimURI)) {
                    if (attributes != null) {
                        String userClaimValue = attributes.get(userClaimURI);
                        if (StringUtils.isNotBlank(userClaimValue)) {
                            if (log.isDebugEnabled()) {
                                log.debug("Using the user claim URI value : " + userClaimValue + " as the user id.");
                            }
                            return userClaimValue;
                        }
                    }
                    throw new IdentityOAuth2Exception("User id found among claims option and user claim URI : "
                            + userClaimURI + " are configured for the " +
                            "SAML federated identity provider : " + identityProvider.getIdentityProviderName() +
                            ", but user claim value is not present in the SAML assertion.");
                } else {
                    throw new IdentityOAuth2Exception("SAML federated authenticator configuration " +
                            IdentityApplicationConstants.Authenticator.SAML2SSO.IS_USER_ID_IN_CLAIMS + " is enabled to " +
                            "the identity provider : " + identityProvider.getIdentityProviderName() + " but User ID " +
                            "Claim URI is not selected in basic claim configuration.");
                }
            } else {
                throw new IdentityOAuth2Exception("UserIdFromClaims configuration is enabled for saml bearer grant but " +
                        "SAML federated authenticator configuration " + IdentityApplicationConstants.Authenticator
                        .SAML2SSO.IS_USER_ID_IN_CLAIMS + " is not enabled to the identity provider : " +
                        identityProvider.getIdentityProviderName());
            }
        } else {
            String nameIdValue = getNameIdValue(assertion);
            if (log.isDebugEnabled()) {
                log.debug("Using the name identifier : " + nameIdValue + " as the user id.");
            }
            return nameIdValue;
        }
    }

    /**
     * Check whether the "user id found among claims" option enabled for the federated identity provider.
     *
     * @param identityProvider
     * @return
     */
    private boolean isUserIdFromClaimsEnabled(IdentityProvider identityProvider) {

        Property isUserIdInClaims = null;
        FederatedAuthenticatorConfig[] fedAuthnConfigs = identityProvider.getFederatedAuthenticatorConfigs();
        if (fedAuthnConfigs != null) {
            FederatedAuthenticatorConfig fedSAMLAuthnConfig = IdentityApplicationManagementUtil.getFederatedAuthenticator
                    (fedAuthnConfigs, IdentityApplicationConstants.Authenticator.SAML2SSO.FED_AUTH_NAME);
            if (fedSAMLAuthnConfig != null) {
                isUserIdInClaims = IdentityApplicationManagementUtil.getProperty(
                        fedSAMLAuthnConfig.getProperties(), IdentityApplicationConstants.Authenticator.SAML2SSO.
                                IS_USER_ID_IN_CLAIMS);
                if (isUserIdInClaims != null && "TRUE".equalsIgnoreCase(isUserIdInClaims.getValue())) {
                    if (log.isDebugEnabled()) {
                        log.debug(IdentityApplicationConstants.Authenticator.SAML2SSO.
                                IS_USER_ID_IN_CLAIMS + " is enabled to the SAML federated identity provider : " +
                                identityProvider.getIdentityProviderName());
                    }
                    return true;
                }
            }
        }
        return false;
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
            XMLObject samlObject = UnmarshallUtils.unmarshall(new String(Base64.decodeBase64(
                    tokReqMsgCtx.getOauth2AccessTokenReqDTO().getAssertion()), StandardCharsets.UTF_8));
            validateAssertionList(samlObject);
            return getAssertion(samlObject);
        } catch (IdentityUnmarshallingException e) {
            if(log.isDebugEnabled()){
                log.debug("Error while unmashalling the assertion", e);
            }
            throw new IdentityOAuth2Exception("Error while unmashalling the assertion", e);
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
            if (ClaimsUtil.isResidentIdp(identityProvider)) {
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

        IdentityProvider identityProvider = getIdentityProvider(assertion, tenantDomain);
        String subjectIdentifier = getUserId(tokReqMsgCtx, identityProvider, assertion);
        if (log.isDebugEnabled()) {
            log.debug("Setting federated user : " + subjectIdentifier + ". with SP tenant domain : " + tenantDomain);
        }
        AuthenticatedUser user =
                AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(subjectIdentifier);
        user.setUserName(subjectIdentifier);
        user.setFederatedIdPName(getIdentityProvider(assertion, getTenantDomain(tokReqMsgCtx))
                .getIdentityProviderName());
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
        IdentityProvider identityProvider = getIdentityProvider(assertion, spTenantDomain);
        String subjectIdentifier = getUserId(tokReqMsgCtx, identityProvider, assertion);
        String userTenantDomain = null;
        if (log.isDebugEnabled()) {
            log.debug("Building local user with assertion subject : " + subjectIdentifier);
        }
        authenticatedUser.setUserStoreDomain(UserCoreUtil.extractDomainFromName(subjectIdentifier));
        authenticatedUser.setUserName(MultitenantUtils.getTenantAwareUsername(UserCoreUtil.removeDomainFromName
                (subjectIdentifier)));

        userTenantDomain = MultitenantUtils.getTenantDomain(subjectIdentifier);
        // From above method userTenantDomain cannot be empty.
        if (!serviceProvider.isSaasApp() && !subjectIdentifier.endsWith(MultitenantConstants
                .SUPER_TENANT_DOMAIN_NAME) && MultitenantConstants.SUPER_TENANT_DOMAIN_NAME
                .equalsIgnoreCase(userTenantDomain)) {
            userTenantDomain = spTenantDomain;
        }

        authenticatedUser.setTenantDomain(userTenantDomain);
        authenticatedUser.setAuthenticatedSubjectIdentifier(authenticatedUser.getUserName(), serviceProvider);
        authenticatedUser.setFederatedIdPName(getIdentityProvider(assertion, getTenantDomain(tokReqMsgCtx))
                .getIdentityProviderName());
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

        String tenantDomain = getTenantDomain(tokReqMsgCtx);
        IdentityProvider identityProvider = getIdentityProvider(assertion, tenantDomain);
        //Check whether NameID value is null before call this method.
        String resourceOwnerUserName = getUserId(tokReqMsgCtx, identityProvider, assertion);
        AuthenticatedUser user = OAuth2Util.getUserFromUserName(resourceOwnerUserName);

        user.setAuthenticatedSubjectIdentifier(resourceOwnerUserName);
        user.setFederatedUser(true);
        user.setFederatedIdPName(getIdentityProvider(assertion, getTenantDomain(tokReqMsgCtx))
                .getIdentityProviderName());
        tokReqMsgCtx.setAuthorizedUser(user);
    }

    /**
     * Validate the signature against the certificate obtained from SAML Sign KeyStore which is defined under
     * Security.SAMLSignKeyStore in carbon.xml.
     *
     * @param assertion assertion.
     * @throws IdentityOAuth2Exception
     */
    protected void validateSignatureAgainstSAMLSignKeyStoreCertificate(Assertion assertion)
            throws IdentityOAuth2Exception {

        try {
            X509Certificate x509Certificate = getCertificateFromSAMLSignKeyStore();
            X509Credential x509Credential = new X509CredentialImpl(x509Certificate);
            SignatureValidator.validate(assertion.getSignature(), x509Credential);
        } catch (SignatureException e) {
            if (StringUtils.isNotEmpty(assertion.getIssuer().getValue())) {
                throw new IdentityOAuth2Exception(
                        "Error while validating the signature from SAML sign keystore for SAML Token Issuer: "
                                + assertion.getIssuer().getValue(), e);
            } else {
                throw new IdentityOAuth2Exception(
                        "Error while validating the signature from SAML sign keystore, SAML Token Issuer is null.", e);
            }
        }
    }

    /**
     * Get the certificate from the SAML Sign KeyStore which is defined under Security.SAMLSignKeyStore in carbon.xml.
     *
     * @return certificate which obtained from SAML Sign Key Store.
     * @throws IdentityOAuth2Exception
     */
    private X509Certificate getCertificateFromSAMLSignKeyStore() throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Getting the certificate from separate SAMLSignKeyStore.");
        }

        String keyStoreLocation = ServerConfiguration.getInstance()
                .getFirstProperty(SECURITY_SAML_SIGN_KEY_STORE_LOCATION);
        try (FileInputStream smalKeystoreFile = new FileInputStream(keyStoreLocation)) {
            String keyStoreType = ServerConfiguration.getInstance().getFirstProperty(SECURITY_SAML_SIGN_KEY_STORE_TYPE);
            KeyStore keyStore = KeyStore.getInstance(keyStoreType);

            char[] keyStorePassword = ServerConfiguration.getInstance()
                    .getFirstProperty(SECURITY_SAML_SIGN_KEY_STORE_PASSWORD).toCharArray();
            keyStore.load(smalKeystoreFile, keyStorePassword);

            KeyStore samlSignKeyStore = keyStore;

            String keyAlias = ServerConfiguration.getInstance()
                    .getFirstProperty(SECURITY_SAML_SIGN_KEY_STORE_KEY_ALIAS);

            return (X509Certificate) samlSignKeyStore.getCertificate(keyAlias);

        } catch (FileNotFoundException e) {
            throw new IdentityOAuth2Exception("Unable to locate SAML sign keystore.", e);
        } catch (IOException e) {
            throw new IdentityOAuth2Exception("Unable to read SAML sign keystore.", e);
        } catch (CertificateException e) {
            throw new IdentityOAuth2Exception("Unable to read certificate from SAML sign keystore.", e);
        } catch (NoSuchAlgorithmException e) {
            throw new IdentityOAuth2Exception("Unable to load algorithm.", e);
        } catch (KeyStoreException e) {
            throw new IdentityOAuth2Exception("Unable to load SAML sign keystore.", e);
        }
    }

    /**
     * Check whether separate configurations for SAML sign KeyStore available.
     *
     * @return true if necessary configurations are defined for sign KeyStore; false otherwise.
     */
    private boolean isSAMLSignKeyStoreConfigured() {

        String keyStoreLocation = ServerConfiguration.getInstance()
                .getFirstProperty(SECURITY_SAML_SIGN_KEY_STORE_LOCATION);
        String keyStoreType = ServerConfiguration.getInstance().getFirstProperty(SECURITY_SAML_SIGN_KEY_STORE_TYPE);
        String keyStorePassword = ServerConfiguration.getInstance()
                .getFirstProperty(SECURITY_SAML_SIGN_KEY_STORE_PASSWORD);
        String keyAlias = ServerConfiguration.getInstance().getFirstProperty(SECURITY_SAML_SIGN_KEY_STORE_KEY_ALIAS);
        String keyPassword = ServerConfiguration.getInstance()
                .getFirstProperty(SECURITY_SAML_SIGN_KEY_STORE_KEY_PASSWORD);

        return StringUtils.isNotBlank(keyStoreLocation) && StringUtils.isNotBlank(keyStoreType) && StringUtils
                .isNotBlank(keyStorePassword) && StringUtils.isNotBlank(keyAlias) && StringUtils
                .isNotBlank(keyPassword);
    }
}
