/*
 * Copyright (c) 2017-2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.openidconnect;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.action.execution.api.exception.ActionExecutionException;
import org.wso2.carbon.identity.action.execution.api.model.ActionExecutionStatus;
import org.wso2.carbon.identity.action.execution.api.model.ActionType;
import org.wso2.carbon.identity.action.execution.api.model.Error;
import org.wso2.carbon.identity.action.execution.api.model.Failure;
import org.wso2.carbon.identity.action.execution.api.model.FlowContext;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticationMethodNameTranslator;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.IDTokenValidationFailureException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenExtendedAttributes;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.action.preissueidtoken.dto.IDTokenDTO;
import org.wso2.carbon.identity.openidconnect.internal.OpenIDConnectServiceComponentHolder;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCClaims.AUTH_TIME;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCClaims.AZP;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCClaims.IDP_SESSION_KEY;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCClaims.NONCE;
import static org.wso2.carbon.identity.oauth2.token.handlers.grant.RefreshGrantHandler.SESSION_IDENTIFIER;

/**
 * Default IDToken generator for the OpenID Connect Implementation.
 * This IDToken Generator utilizes the Nimbus SDK to build the IDToken.
 */
public class DefaultIDTokenBuilder implements org.wso2.carbon.identity.openidconnect.IDTokenBuilder {

    private static final String AUTHORIZATION_CODE = "AuthorizationCode";
    private static final String INBOUND_AUTH2_TYPE = "oauth2";
    private static final String TOKEN_REQUEST_MESSAGE_CONTEXT = "tokenReqMessageContext";
    private static final String AUTHZ_REQUEST_MESSAGE_CONTEXT = "authzReqMessageContext";
    private static final String REQUEST_TYPE = "requestType";
    private static final String REQUEST_TYPE_TOKEN = "token";
    private static final String REQUEST_TYPE_AUTHZ = "authz";
    private static final String ID_TOKEN_DTO = "idTokenDTO";

    private static final Log log = LogFactory.getLog(DefaultIDTokenBuilder.class);
    private JWSAlgorithm signatureAlgorithm;
    private JWEAlgorithm encryptionAlgorithm;
    private EncryptionMethod encryptionMethod;

    public DefaultIDTokenBuilder() throws IdentityOAuth2Exception {
        // Map signature algorithm from identity.xml to nimbus format, this is a one time configuration.
        signatureAlgorithm = OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm(
                OAuthServerConfiguration.getInstance().getIdTokenSignatureAlgorithm());
    }

    /**
     * Create an oAuthAppDO object using client id and set encryption algorithm and encryption method.
     * @param clientId  ID of the client.
     * @throws IdentityOAuth2Exception
     */
    private void setupEncryptionAlgorithms(OAuthAppDO oAuthAppDO, String clientId) throws IdentityOAuth2Exception {

        encryptionAlgorithm = OAuth2Util.mapEncryptionAlgorithmForJWEAlgorithm(
                    oAuthAppDO.getIdTokenEncryptionAlgorithm());
        encryptionMethod = OAuth2Util.mapEncryptionMethodForJWEAlgorithm(oAuthAppDO.getIdTokenEncryptionMethod());

        if (log.isDebugEnabled()) {
            log.debug("Id token encryption is enabled using encryption algorithm: " + encryptionAlgorithm +
                    " and encryption method: " + encryptionMethod + ", for client: " + clientId);
        }
    }

    @Override
    public String buildIDToken(OAuthTokenReqMessageContext tokenReqMsgCtxt,
                               OAuth2AccessTokenRespDTO tokenRespDTO) throws IdentityOAuth2Exception {

        String clientId = tokenReqMsgCtxt.getOauth2AccessTokenReqDTO().getClientId();
        String spTenantDomain = getSpTenantDomain(tokenReqMsgCtxt);
        // Checks if the current application is a system app and sets the value to thread local
        if (StringUtils.isNotEmpty(spTenantDomain) && StringUtils.isNotEmpty(clientId)) {
            IdentityUtil.threadLocalProperties.get().put(IdentityCoreConstants.IS_SYSTEM_APPLICATION,
                    IdentityTenantUtil.isSystemApplication(spTenantDomain, clientId));
        }
        try {
            String requestURL = tokenReqMsgCtxt.getOauth2AccessTokenReqDTO().getHttpServletRequestWrapper()
                    .getRequestURL().toString();
            String idTokenIssuer = OAuth2Util.getIdTokenIssuer(spTenantDomain, clientId,
                    OAuth2Util.isMtlsRequest(requestURL));
            String accessToken = tokenRespDTO.getAccessToken();
            JWSAlgorithm idTokenSignatureAlgorithm = signatureAlgorithm;

            // Initialize OAuthAppDO using the client ID.
            OAuthAppDO oAuthAppDO;
            try {
                oAuthAppDO = OAuth2Util.getAppInformationByClientId(clientId, spTenantDomain);
            } catch (InvalidOAuthClientException e) {
                String error = "Error occurred while getting app information for client_id: " + clientId;
                throw new IdentityOAuth2Exception(error, e);
            }
            // Retrieve application id token signature algorithm
            if (StringUtils.isNotEmpty(oAuthAppDO.getIdTokenSignatureAlgorithm())) {
                idTokenSignatureAlgorithm = OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm(
                        oAuthAppDO.getIdTokenSignatureAlgorithm());
            }

            long idTokenValidityInMillis = getIDTokenExpiryInMillis(oAuthAppDO);
            long currentTimeInMillis = Calendar.getInstance().getTimeInMillis();

            AuthenticatedUser authorizedUser = tokenReqMsgCtxt.getAuthorizedUser();
            String subjectClaim =
                    getSubjectClaim(tokenReqMsgCtxt, tokenRespDTO, clientId, spTenantDomain, authorizedUser);
            // Get subject identifier according to the configured subject type.
            subjectClaim = OIDCClaimUtil.getSubjectClaim(subjectClaim, oAuthAppDO);

            String nonceValue = null;
            String idpSessionKey = null;
            long authTime = 0;
            String acrValue = null;
            List<String> amrValues = Collections.emptyList();

            // AuthorizationCode only available for authorization code grant type
            if (getAuthorizationCode(tokenReqMsgCtxt) != null) {
                AuthorizationGrantCacheEntry authzGrantCacheEntry =
                        getAuthorizationGrantCacheEntryFromCode(getAuthorizationCode(tokenReqMsgCtxt));
                if (authzGrantCacheEntry != null) {
                    nonceValue = authzGrantCacheEntry.getNonceValue();
                    acrValue = authzGrantCacheEntry.getSelectedAcrValue();
                    if (isAuthTimeRequired(authzGrantCacheEntry)) {
                        authTime = authzGrantCacheEntry.getAuthTime();
                    }
                    amrValues = authzGrantCacheEntry.getAmrList();
                    idpSessionKey = getIdpSessionKey(authzGrantCacheEntry);
                }
            } else {
                amrValues = tokenReqMsgCtxt.getOauth2AccessTokenReqDTO().getAuthenticationMethodReferences();
                if (OAuthConstants.GrantTypes.REFRESH_TOKEN.equalsIgnoreCase(
                        tokenReqMsgCtxt.getOauth2AccessTokenReqDTO().getGrantType())) {
                    AuthorizationGrantCacheEntry authorizationGrantCacheEntryFromToken =
                            getAuthorizationGrantCacheEntryFromToken(tokenRespDTO.getAccessToken());
                    if (authorizationGrantCacheEntryFromToken != null) {
                        if (isAuthTimeRequired(authorizationGrantCacheEntryFromToken)) {
                            authTime = authorizationGrantCacheEntryFromToken.getAuthTime();
                        }
                    }
                }
                if (!OAuthConstants.GrantTypes.PASSWORD.equalsIgnoreCase(
                        tokenReqMsgCtxt.getOauth2AccessTokenReqDTO().getGrantType())) {
                    idpSessionKey = getIdpSessionKey(accessToken);
                    if (idpSessionKey == null && tokenReqMsgCtxt.getProperty(SESSION_IDENTIFIER) != null) {
                        idpSessionKey = tokenReqMsgCtxt.getProperty(SESSION_IDENTIFIER).toString();
                    }
                }
            }

            if (log.isDebugEnabled()) {
                log.debug(buildDebugMessage(idTokenIssuer, subjectClaim, nonceValue, idTokenValidityInMillis,
                        currentTimeInMillis));
            }

            List<String> audience = OAuth2Util.getOIDCAudience(clientId, oAuthAppDO);

            JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
            jwtClaimsSetBuilder.jwtID(UUID.randomUUID().toString());
            jwtClaimsSetBuilder.issuer(idTokenIssuer);
            jwtClaimsSetBuilder.claim(AZP, clientId);
            if (authTime != 0) {
                jwtClaimsSetBuilder.claim(AUTH_TIME, authTime / 1000);
            }
            if (nonceValue != null) {
                jwtClaimsSetBuilder.claim(NONCE, nonceValue);
            }
            if (StringUtils.isNotEmpty(acrValue)) {
                jwtClaimsSetBuilder.claim(OAuthConstants.ACR, acrValue);
            }
            if (amrValues != null) {
                jwtClaimsSetBuilder.claim(OAuthConstants.AMR, translateAmrToResponse(amrValues));
            }
            if (idpSessionKey != null) {
                jwtClaimsSetBuilder.claim(IDP_SESSION_KEY, idpSessionKey);
            }
            AccessTokenExtendedAttributes accessTokenExtendedAttributes =
                    tokenReqMsgCtxt.getOauth2AccessTokenReqDTO().getAccessTokenExtendedAttributes();
            if (accessTokenExtendedAttributes != null && accessTokenExtendedAttributes.getParameters() != null) {
                for (Map.Entry<String, String> entry : accessTokenExtendedAttributes.getParameters().entrySet()) {
                    jwtClaimsSetBuilder.claim(entry.getKey(), entry.getValue());
                }
            }
            setUserRealm(authorizedUser, jwtClaimsSetBuilder);
            setAdditionalClaims(tokenReqMsgCtxt, tokenRespDTO, jwtClaimsSetBuilder);

            tokenReqMsgCtxt.addProperty(OAuthConstants.ACCESS_TOKEN, accessToken);
            tokenReqMsgCtxt.addProperty(MultitenantConstants.TENANT_DOMAIN, getSpTenantDomain(tokenReqMsgCtxt));
            if (tokenRespDTO.getIsConsentedToken()) {
                tokenReqMsgCtxt.setConsentedToken(tokenRespDTO.getIsConsentedToken());
            }
            jwtClaimsSetBuilder.subject(subjectClaim);
            Map<String, Object> oidcClaimSet = handleOIDCCustomClaims(tokenReqMsgCtxt, jwtClaimsSetBuilder);

            IDTokenDTO idTokenDTO = getIDTokenDTO(tokenReqMsgCtxt, jwtClaimsSetBuilder, audience,
                    idTokenValidityInMillis, oidcClaimSet);

            // Execute the Pre-Issue ID Token Action if configured. The changes done by the action are reflected in the
            // IDTokenDTO.
            if (checkExecutePreIssueIdTokensActions(tokenReqMsgCtxt)) {
                ActionExecutionStatus<?> executionStatus = executePreIssueIdTokenActions(tokenReqMsgCtxt, idTokenDTO,
                        oAuthAppDO);
                if (executionStatus != null && (executionStatus.getStatus() == ActionExecutionStatus.Status.FAILED ||
                        executionStatus.getStatus() == ActionExecutionStatus.Status.ERROR)) {
                    handleFailureOrError(executionStatus);
                }
            }

            JWTClaimsSet jwtClaimsSet = buildJWTClaimSetIdTokenDto(idTokenDTO);

            if (isInvalidToken(jwtClaimsSet)) {
                throw new IDTokenValidationFailureException(
                        "Error while validating ID Token token for required claims");
            }

            if (isUnsignedIDToken()) {
                return new PlainJWT(jwtClaimsSet).serialize();
            }

            return getIDToken(clientId, spTenantDomain, jwtClaimsSet, oAuthAppDO,
                    getSigningTenantDomain(tokenReqMsgCtxt), idTokenSignatureAlgorithm);
        } finally {
            // Clean up thread local to prevent thread local pollution across requests.
            IdentityUtil.threadLocalProperties.get().remove(IdentityCoreConstants.IS_SYSTEM_APPLICATION);
            if (log.isDebugEnabled()) {
                log.debug("Removed " + IdentityCoreConstants.IS_SYSTEM_APPLICATION +
                        " thread local property to prevent pollution.");
            }
        }
    }

    @Override
    public String buildIDToken(OAuthAuthzReqMessageContext authzReqMessageContext,
                               OAuth2AuthorizeRespDTO tokenRespDTO) throws IdentityOAuth2Exception {

        String accessToken = tokenRespDTO.getAccessToken();
        String clientId = authzReqMessageContext.getAuthorizationReqDTO().getConsumerKey();
        String spTenantDomain = getSpTenantDomain(authzReqMessageContext);
        Object isMtls = authzReqMessageContext.getProperty(OAuthConstants.IS_MTLS_REQUEST);
        boolean isMtlsRequest = isMtls != null && Boolean.parseBoolean(isMtls.toString());
        String issuer = OAuth2Util.getIdTokenIssuer(spTenantDomain, isMtlsRequest);
        JWSAlgorithm idTokenSignatureAlgorithm = signatureAlgorithm;

        // Initialize OAuthAppDO using the client ID.
        OAuthAppDO oAuthAppDO;
        try {
            oAuthAppDO = OAuth2Util.getAppInformationByClientId(clientId);
        } catch (InvalidOAuthClientException e) {
            String error = "Error occurred while getting app information for client_id: " + clientId;
            throw new IdentityOAuth2Exception(error, e);
        }
        // Retrieve application id token signature algorithm
        if (StringUtils.isNotEmpty(oAuthAppDO.getIdTokenSignatureAlgorithm())) {
            idTokenSignatureAlgorithm = OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm(
                    oAuthAppDO.getIdTokenSignatureAlgorithm());
        }

        // Get subject from Authenticated Subject Identifier
        AuthenticatedUser authorizedUser = authzReqMessageContext.getAuthorizationReqDTO().getUser();
        String subject =
                getSubjectClaim(authzReqMessageContext, tokenRespDTO, clientId, spTenantDomain, authorizedUser);
        // Get subject identifier according to the configured subject type.
        subject = OIDCClaimUtil.getSubjectClaim(subject, oAuthAppDO);

        String nonceValue = authzReqMessageContext.getAuthorizationReqDTO().getNonce();
        String acrValue = authzReqMessageContext.getAuthorizationReqDTO().getSelectedAcr();
        List<String> amrValues = Collections.emptyList(); //TODO:
        String idpSessionKey = getIdpSessionKey(authzReqMessageContext);

        String[] amrValueArray =
                (String[]) (authzReqMessageContext.getAuthorizationReqDTO().getProperty(OAuthConstants.AMR));
        if (ArrayUtils.isNotEmpty(amrValueArray)) {
            amrValues = Arrays.asList(amrValueArray);
        }
        long idTokenLifeTimeInMillis = getIDTokenExpiryInMillis(oAuthAppDO);
        long currentTimeInMillis = Calendar.getInstance().getTimeInMillis();

        if (log.isDebugEnabled()) {
            log.debug(buildDebugMessage(issuer, subject, nonceValue, idTokenLifeTimeInMillis, currentTimeInMillis));
        }

        JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
        jwtClaimsSetBuilder.jwtID(UUID.randomUUID().toString());
        jwtClaimsSetBuilder.issuer(issuer);

        // Set the audience
        List<String> audience = OAuth2Util.getOIDCAudience(clientId, oAuthAppDO);

        jwtClaimsSetBuilder.claim(AZP, clientId);

        long authTime = getAuthTime(authzReqMessageContext);
        if (authTime != 0) {
            jwtClaimsSetBuilder.claim(AUTH_TIME, authTime / 1000);
        }
        if (nonceValue != null) {
            jwtClaimsSetBuilder.claim(OAuthConstants.OIDCClaims.NONCE, nonceValue);
        }
        if (StringUtils.isNotEmpty(acrValue)) {
            jwtClaimsSetBuilder.claim("acr", acrValue);
        }
        if (amrValues != null) {
            jwtClaimsSetBuilder.claim("amr", translateAmrToResponse(amrValues));
        }
        if (idpSessionKey != null) {
            jwtClaimsSetBuilder.claim(IDP_SESSION_KEY, idpSessionKey);
        }
        setUserRealm(authorizedUser, jwtClaimsSetBuilder);
        setAdditionalClaims(authzReqMessageContext, tokenRespDTO, jwtClaimsSetBuilder);

        if (StringUtils.isNotBlank(accessToken)) {
            authzReqMessageContext.addProperty(OAuthConstants.ACCESS_TOKEN, accessToken);
        }
        authzReqMessageContext
                .addProperty(MultitenantConstants.TENANT_DOMAIN, getSpTenantDomain(authzReqMessageContext));
        jwtClaimsSetBuilder.subject(subject);
        Map<String, Object> oidcClaimSet = handleCustomOIDCClaims(authzReqMessageContext, jwtClaimsSetBuilder);

        IDTokenDTO idTokenDTO = getIDTokenDTO(authzReqMessageContext, jwtClaimsSetBuilder, audience,
                idTokenLifeTimeInMillis, oidcClaimSet);

        // Execute the Pre-Issue ID Token Action if configured. The changes done by the action are reflected in the
        // IDTokenDTO.
        if (checkExecutePreIssueIdTokensActions(authzReqMessageContext)) {
            ActionExecutionStatus<?> executionStatus = executePreIssueIdTokenActions(authzReqMessageContext,
                    idTokenDTO);
            if (executionStatus != null && (executionStatus.getStatus() == ActionExecutionStatus.Status.FAILED ||
                    executionStatus.getStatus() == ActionExecutionStatus.Status.ERROR)) {
                handleFailureOrError(executionStatus);
            }
        }

        JWTClaimsSet jwtClaimsSet = buildJWTClaimSetIdTokenDto(idTokenDTO);
        if (isUnsignedIDToken()) {
            return new PlainJWT(jwtClaimsSet).serialize();
        }

        return getIDToken(clientId, spTenantDomain, jwtClaimsSet, oAuthAppDO,
                getSigningTenantDomain(authzReqMessageContext), idTokenSignatureAlgorithm);
    }

    private String getIDToken(String clientId, String spTenantDomain, JWTClaimsSet jwtClaimsSet, OAuthAppDO oAuthAppDO,
                              String signingTenantDomain, JWSAlgorithm signatureAlgorithm)
            throws IdentityOAuth2Exception {

        if (oAuthAppDO.isIdTokenEncryptionEnabled()) {
            checkIfPublicCertConfiguredForEncryption(clientId, spTenantDomain);
            setupEncryptionAlgorithms(oAuthAppDO, clientId);
            return OAuth2Util.encryptJWT(jwtClaimsSet, signatureAlgorithm, signingTenantDomain,
                    encryptionAlgorithm, encryptionMethod, spTenantDomain,
                    clientId).serialize();
        } else {
            return OAuth2Util.signJWT(jwtClaimsSet, signatureAlgorithm, signingTenantDomain).serialize();
        }
    }

    protected String getSubjectClaim(OAuthTokenReqMessageContext tokenReqMessageContext,
                                     OAuth2AccessTokenRespDTO tokenRespDTO,
                                     String clientId,
                                     String spTenantDomain,
                                     AuthenticatedUser authorizedUser) throws IdentityOAuth2Exception {

        return authorizedUser.getAuthenticatedSubjectIdentifier();
    }

    protected String getSubjectClaim(OAuthAuthzReqMessageContext authzReqMessageContext,
                                     OAuth2AuthorizeRespDTO authorizeRespDTO,
                                     String clientId,
                                     String spTenantDomain,
                                     AuthenticatedUser authorizedUser) throws IdentityOAuth2Exception {

        return authorizedUser.getAuthenticatedSubjectIdentifier();
    }

    private String buildDebugMessage(String issuer, String subject, String nonceValue, long idTokenLifeTimeInMillis,
                                     long currentTimeInMillis) {
        return (new StringBuilder())
                .append("Using issuer ").append(issuer).append("\n")
                .append("Subject ").append(subject).append("\n")
                .append("ID Token life time ").append(idTokenLifeTimeInMillis / 1000).append("\n")
                .append("Current time ").append(currentTimeInMillis / 1000).append("\n")
                .append("Nonce Value ").append(nonceValue).append("\n")
                .append("Signature Algorithm ").append(signatureAlgorithm).append("\n")
                .toString();
    }

    private boolean isInvalidToken(JWTClaimsSet jwtClaimsSet) {
        return !isValidIdToken(jwtClaimsSet);
    }

    private boolean isEssentialClaim(AuthorizationGrantCacheEntry authorizationGrantCacheEntry, String oidcClaimUri) {
        return isEssentialClaim(authorizationGrantCacheEntry.getEssentialClaims(), oidcClaimUri);
    }

    private boolean isEssentialClaim(String essentialClaims, String oidcClaimUri) {
        return StringUtils.isNotBlank(essentialClaims) &&
                OAuth2Util.getEssentialClaims(essentialClaims, OAuthConstants.ID_TOKEN).contains(oidcClaimUri);
    }

    private boolean isMaxAgePresentInAuthzRequest(AuthorizationGrantCacheEntry authorizationGrantCacheEntry) {
        return authorizationGrantCacheEntry.getMaxAge() != 0;
    }

    private boolean isUnsignedIDToken() {
        return JWSAlgorithm.NONE.getName().equals(signatureAlgorithm.getName());
    }

    private String getAuthorizationCode(OAuthTokenReqMessageContext tokenReqMsgCtxt) {
        return (String) tokenReqMsgCtxt.getProperty(AUTHORIZATION_CODE);
    }

    private String getSpTenantDomain(OAuthTokenReqMessageContext tokReqMsgCtx) {
        return tokReqMsgCtx.getOauth2AccessTokenReqDTO().getTenantDomain();
    }

    private Map<String, Object> handleOIDCCustomClaims(OAuthTokenReqMessageContext tokReqMsgCtx,
                                                       JWTClaimsSet.Builder jwtClaimsSetBuilder)
            throws IdentityOAuth2Exception {

        JWTClaimsSet existingClaims = jwtClaimsSetBuilder.build();
        JWTClaimsSet.Builder jwtClaimsSetBuilderCopy = new JWTClaimsSet.Builder(existingClaims);
        Map<String, Object> returningClaims = new HashMap<>();

        CustomClaimsCallbackHandler claimsCallBackHandler =
                OAuthServerConfiguration.getInstance().getOpenIDConnectCustomClaimsCallbackHandler();
        JWTClaimsSet customClaimsAddedJWTClaimSet =
                claimsCallBackHandler.handleCustomClaims(jwtClaimsSetBuilderCopy, tokReqMsgCtx);

        // The CustomClaimsCallbackHandler is responsible for managing custom claims in the ID token.
        // When a custom claim has the same name as an existing claim, the handler determines whether to
        // override or preserve the existing value. This logic respects the handler's decision by:
        // - Adding truly new claims (no name collision) to returningClaims
        // - Updating the builder with custom claims that have matching names, allowing the handler's
        //   choice (whether to override or keep the original) to take effect.
        Map<String, Object> existingClaimMap = existingClaims.getClaims();
        for (Map.Entry<String, Object> entry : customClaimsAddedJWTClaimSet.getClaims().entrySet()) {
            if (!existingClaimMap.containsKey(entry.getKey())) {
                returningClaims.put(entry.getKey(), entry.getValue());
            } else {
                jwtClaimsSetBuilder.claim(entry.getKey(), entry.getValue());
            }
        }
        return returningClaims;
    }

    private String getSigningTenantDomain(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {

        boolean isJWTSignedWithSPKey = OAuthServerConfiguration.getInstance().isJWTSignedWithSPKey();
        String applicationResidentOrgId = PrivilegedCarbonContext.getThreadLocalCarbonContext()
                .getApplicationResidentOrganizationId();
        /*
         If applicationResidentOrgId is not empty, then the request comes for an application which is
         registered directly in the organization of the applicationResidentOrgId. In this case, the tenant domain
         that needs to be signing the token should be extracted from the application OIDC configurations. If that
         is not available then the root organization will be selected as the signing tenant domain.
        */
        if (StringUtils.isNotEmpty(applicationResidentOrgId)) {
            return OAuth2Util.getTenantDomainByApplicationTokenIssuer(
                    tokReqMsgCtx.getOauth2AccessTokenReqDTO().getClientId(), applicationResidentOrgId);
        } else if (isJWTSignedWithSPKey) {
            return (String) tokReqMsgCtx.getProperty(MultitenantConstants.TENANT_DOMAIN);
        } else {
            return tokReqMsgCtx.getAuthorizedUser().getTenantDomain();
        }
    }

    private long getAuthTime(OAuthAuthzReqMessageContext authzReqMessageContext) {
        long authTime = 0;
        if (isAuthTimeRequired(authzReqMessageContext.getAuthorizationReqDTO())) {
            authTime = authzReqMessageContext.getAuthorizationReqDTO().getAuthTime();
        }
        return authTime;
    }

    /**
     * Checks whether 'auth_time' claim is required to be sent in the id_token response. 'auth_time' needs to be sent
     * in the id_token if it is requested as an essential claim or when max_age parameter is sent in the
     * authorization request. Refer: http://openid.net/specs/openid-connect-core-1_0.html#IDToken
     *
     * @param authzGrantCacheEntry
     * @return whether auth_time needs to be sent in the id_token response.
     */
    private boolean isAuthTimeRequired(AuthorizationGrantCacheEntry authzGrantCacheEntry) {
        return isMaxAgePresentInAuthzRequest(authzGrantCacheEntry) || isEssentialClaim(authzGrantCacheEntry, AUTH_TIME);
    }

    private boolean isAuthTimeRequired(OAuth2AuthorizeReqDTO oAuth2AuthorizeReqDTO) {
        return oAuth2AuthorizeReqDTO.getMaxAge() != 0 ||
                isEssentialClaim(oAuth2AuthorizeReqDTO.getEssentialClaims(), AUTH_TIME);
    }

    private Date getIdTokenExpiryInMillis(long currentTimeInMillis, long lifetimeInMillis) {
        return new Date(currentTimeInMillis + lifetimeInMillis);
    }

    private Map<String, Object> handleCustomOIDCClaims(OAuthAuthzReqMessageContext request,
                                                       JWTClaimsSet.Builder jwtClaimsSetBuilder)
            throws IdentityOAuth2Exception {

        JWTClaimsSet existingClaims = jwtClaimsSetBuilder.build();
        JWTClaimsSet.Builder jwtClaimsSetBuilderCopy = new JWTClaimsSet.Builder(existingClaims);
        Map<String, Object> returningClaims = new HashMap<>();

        CustomClaimsCallbackHandler claimsCallBackHandler =
                OAuthServerConfiguration.getInstance().getOpenIDConnectCustomClaimsCallbackHandler();
        JWTClaimsSet customClaimsAddedJWTClaimSet =
                claimsCallBackHandler.handleCustomClaims(jwtClaimsSetBuilderCopy, request);

        // The CustomClaimsCallbackHandler is responsible for managing custom claims in the ID token.
        // When a custom claim has the same name as an existing claim, the handler determines whether to
        // override or preserve the existing value. This logic respects the handler's decision by:
        // - Adding truly new claims (no name collision) to returningClaims
        // - Updating the builder with custom claims that have matching names, allowing the handler's
        //   choice (whether to override or keep the original) to take effect.
        Map<String, Object> existingClaimMap = existingClaims.getClaims();
        for (Map.Entry<String, Object> entry : customClaimsAddedJWTClaimSet.getClaims().entrySet()) {
            if (!existingClaimMap.containsKey(entry.getKey())) {
                returningClaims.put(entry.getKey(), entry.getValue());
            } else {
                jwtClaimsSetBuilder.claim(entry.getKey(), entry.getValue());
            }
        }
        return returningClaims;
    }

    private String getSpTenantDomain(OAuthAuthzReqMessageContext request) {
        return request.getAuthorizationReqDTO().getTenantDomain();
    }

    private String getSigningTenantDomain(OAuthAuthzReqMessageContext request) {
        boolean isJWTSignedWithSPKey = OAuthServerConfiguration.getInstance().isJWTSignedWithSPKey();
        String signingTenantDomain;
        if (isJWTSignedWithSPKey) {
            signingTenantDomain = (String) request.getProperty(MultitenantConstants.TENANT_DOMAIN);
        } else {
            signingTenantDomain = request.getAuthorizationReqDTO().getUser().getTenantDomain();
        }
        return signingTenantDomain;
    }

    /**
     * sign JWT token from RSA algorithm
     *
     * @param jwtClaimsSet           contains JWT body
     * @param tokenReqMessageContext
     * @return signed JWT token
     * @throws IdentityOAuth2Exception
     */
    @Deprecated
    protected String signJWTWithRSA(JWTClaimsSet jwtClaimsSet,
                                    OAuthTokenReqMessageContext tokenReqMessageContext) throws IdentityOAuth2Exception {
        String tenantDomain = getSigningTenantDomain(tokenReqMessageContext);
        return OAuth2Util.signJWTWithRSA(jwtClaimsSet, signatureAlgorithm, tenantDomain).serialize();
    }

    /**
     * sign JWT token from RSA algorithm
     *
     * @param jwtClaimsSet           contains JWT body
     * @param authzReqMessageContext
     * @return signed JWT token
     * @throws IdentityOAuth2Exception
     */
    @Deprecated
    protected String signJWTWithRSA(JWTClaimsSet jwtClaimsSet,
                                    OAuthAuthzReqMessageContext authzReqMessageContext) throws IdentityOAuth2Exception {
        String signingTenantDomain = getSigningTenantDomain(authzReqMessageContext);
        return OAuth2Util.signJWTWithRSA(jwtClaimsSet, signatureAlgorithm, signingTenantDomain).serialize();
    }

    /**
     * @param authorizationCode
     * @return AuthorizationGrantCacheEntry contains user attributes and nonce value
     */
    private AuthorizationGrantCacheEntry getAuthorizationGrantCacheEntryFromCode(String authorizationCode) {

        AuthorizationGrantCacheKey authorizationGrantCacheKey = new AuthorizationGrantCacheKey(authorizationCode);
        return AuthorizationGrantCache.getInstance().getValueFromCacheByCode(authorizationGrantCacheKey);
    }

    /**
     * Retrieve Authorization Grant Cache entry using an Access token.
     *
     * @param accessToken   Access token.
     * @return              AuthorizationGrantCacheEntry containing user attributes and nonce value.
     */
    private AuthorizationGrantCacheEntry getAuthorizationGrantCacheEntryFromToken(String accessToken) {

        AuthorizationGrantCacheKey cacheKey = new AuthorizationGrantCacheKey(accessToken);
        return AuthorizationGrantCache.getInstance().getValueFromCacheByToken(cacheKey);
    }

    /**
     * Generic Signing function
     *
     * @param jwtClaimsSet    contains JWT body
     * @param tokenMsgContext
     * @return signed JWT token
     * @throws IdentityOAuth2Exception
     */
    @Deprecated
    protected String signJWT(JWTClaimsSet jwtClaimsSet,
                             OAuthTokenReqMessageContext tokenMsgContext) throws IdentityOAuth2Exception {
        if (isRSA(signatureAlgorithm)) {
            return signJWTWithRSA(jwtClaimsSet, tokenMsgContext);
        } else if (isHMAC(signatureAlgorithm)) {
            // return signWithHMAC(jwtClaimsSet,jwsAlgorithm,request); implementation need to be done
            return null;
        } else {
            // return signWithEC(jwtClaimsSet,jwsAlgorithm,request); implementation need to be done
            return null;
        }
    }

    private boolean isRSA(JWSAlgorithm signatureAlgorithm) {
        return JWSAlgorithm.RS256.equals(signatureAlgorithm) || JWSAlgorithm.RS384.equals(signatureAlgorithm) ||
                JWSAlgorithm.RS512.equals(signatureAlgorithm);
    }

    /**
     * Generic Signing function
     *
     * @param jwtClaimsSet           contains JWT body
     * @param authzReqMessageContext
     * @return signed JWT token
     * @throah ws IdentityOAuth2Exception
     */
    @Deprecated
    protected String signJWT(JWTClaimsSet jwtClaimsSet,
                             OAuthAuthzReqMessageContext authzReqMessageContext) throws IdentityOAuth2Exception {

        if (isRSA(signatureAlgorithm)) {
            return signJWTWithRSA(jwtClaimsSet, authzReqMessageContext);
        } else if (isHMAC(signatureAlgorithm)) {
            // return signWithHMAC(jwtClaimsSet,jwsAlgorithm,request); implementation need to be done
            return null;
        } else {
            // return signWithEC(jwtClaimsSet,jwsAlgorithm,request); implementation need to be done
            return null;
        }
    }

    private boolean isHMAC(JWSAlgorithm signatureAlgorithm) {
        return JWSAlgorithm.HS256.equals(signatureAlgorithm) || JWSAlgorithm.HS384.equals(signatureAlgorithm) ||
                JWSAlgorithm.HS512.equals(signatureAlgorithm);
    }

    /**
     * This method map signature algorithm define in identity.xml to nimbus
     * signature algorithm
     * format, Strings are defined inline hence there are not being used any
     * where
     *
     * @param signatureAlgorithm signature algorithm
     * @return mapped JWSAlgorithm
     * @throws IdentityOAuth2Exception
     */
    @Deprecated
    protected JWSAlgorithm mapSignatureAlgorithm(String signatureAlgorithm) throws IdentityOAuth2Exception {
        return OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm(signatureAlgorithm);
    }

    /**
     * This method maps signature algorithm define in identity.xml to digest algorithms to generate the at_hash
     *
     * @param signatureAlgorithm signature algorithm
     * @return mapped digest algorithm
     * @throws IdentityOAuth2Exception
     */
    @Deprecated
    protected String mapDigestAlgorithm(Algorithm signatureAlgorithm) throws IdentityOAuth2Exception {
        return OAuth2Util.mapDigestAlgorithm(signatureAlgorithm);
    }

    /**
     * Method to check whether id token contains the required claims(iss,sub,aud,exp,iat) defined by the oidc spec
     *
     * @param jwtClaimsSet jwt claim set
     * @return true or false(whether id token contains the required claims)
     */
    private boolean isValidIdToken(JWTClaimsSet jwtClaimsSet) {

        if (StringUtils.isBlank(jwtClaimsSet.getIssuer())) {
            if (log.isDebugEnabled()) {
                log.debug("ID token does not have required issuer claim");
            }
            return false;
        }
        if (StringUtils.isBlank(jwtClaimsSet.getSubject())) {
            if (log.isDebugEnabled()) {
                log.debug("ID token does not have required subject claim");
            }
            return false;
        }
        if (jwtClaimsSet.getAudience() == null) {
            if (log.isDebugEnabled()) {
                log.debug("ID token does not have required audience claim");
            }
            return false;
        }
        if (jwtClaimsSet.getExpirationTime() == null) {
            if (log.isDebugEnabled()) {
                log.debug("ID token does not have required expiration time claim");
            }
            return false;
        }
        if (jwtClaimsSet.getIssueTime() == null) {
            if (log.isDebugEnabled()) {
                log.debug("ID token does not have required issued time claim");
            }
            return false;
        }
        // All mandatory claims are present.
        return true;
    }

    private long getIDTokenExpiryInMillis(OAuthAppDO oAuthAppDO) {
        return oAuthAppDO.getIdTokenExpiryTime() * 1000L;
    }

    /**
     * Adding new claims into ID Token using ClaimProvider Service.
     *
     * @param tokenReqMsgCtxt OAuthTokenReqMessageContext
     * @param tokenRespDTO OAuth2AccessTokenRespDTO
     * @param jwtClaimsSetBuilder contains JWT body
     * @throws IdentityOAuth2Exception
     */
    private void setAdditionalClaims(OAuthTokenReqMessageContext tokenReqMsgCtxt,
                                     OAuth2AccessTokenRespDTO tokenRespDTO,
                                     JWTClaimsSet.Builder jwtClaimsSetBuilder)
            throws IdentityOAuth2Exception {
        List<ClaimProvider> claimProviders = getClaimProviders();
        if (CollectionUtils.isNotEmpty(claimProviders)) {
            for (ClaimProvider claimProvider : claimProviders) {
                Map<String, Object> additionalIdTokenClaims =
                        claimProvider.getAdditionalClaims(tokenReqMsgCtxt, tokenRespDTO);
                setAdditionalClaimSet(jwtClaimsSetBuilder, additionalIdTokenClaims);
            }
        }
    }

    /**
     * Adding new claims into ID Token using ClaimProvider Service.
     *
     * @param authzReqMessageContext OAuthAuthzReqMessageContext
     * @param authorizeRespDTO OAuth2AuthorizeRespDTO
     * @param jwtClaimsSetBuilder contains JWT body
     * @throws IdentityOAuth2Exception
     */
    private void setAdditionalClaims(OAuthAuthzReqMessageContext authzReqMessageContext,
                                     OAuth2AuthorizeRespDTO authorizeRespDTO,
                                     JWTClaimsSet.Builder jwtClaimsSetBuilder)
            throws IdentityOAuth2Exception {
        List<ClaimProvider> claimProviders = getClaimProviders();
        if (CollectionUtils.isNotEmpty(claimProviders)) {
            for (ClaimProvider claimProvider : claimProviders) {
                Map<String, Object> additionalIdTokenClaims =
                        claimProvider.getAdditionalClaims(authzReqMessageContext, authorizeRespDTO);
                setAdditionalClaimSet(jwtClaimsSetBuilder, additionalIdTokenClaims);
            }
        }
    }

    private List<ClaimProvider> getClaimProviders() {
        return OpenIDConnectServiceComponentHolder.getInstance().getClaimProviders();
    }

    /**
     * A map with claim names and corresponding claim values is passed and all are inserted into jwtClaimSet.
     *
     * @param jwtClaimsSetBuilder contains JWT body
     * @param additionalIdTokenClaims a map with claim names and corresponding claim values
     */
    private void setAdditionalClaimSet(JWTClaimsSet.Builder jwtClaimsSetBuilder,
                                       Map<String, Object> additionalIdTokenClaims) {

        if (MapUtils.isNotEmpty(additionalIdTokenClaims)) {
            for (Map.Entry<String, Object> entry : additionalIdTokenClaims.entrySet()) {
                jwtClaimsSetBuilder.claim(entry.getKey(), entry.getValue());
            }
            if (log.isDebugEnabled()) {
                for (Map.Entry<String, Object> entry : additionalIdTokenClaims.entrySet()) {
                    log.debug("Additional claim added to JWTClaimSet, key: " + entry.getKey() + ", value: " +
                            entry.getValue());
                }
            }
        }

    }

    /**
     * +     * Converts the internal representation to external (response) form.
     * +     * The resultant list will not have any duplicate values.
     * +     * @param internalList
     * +     * @return a list of amr values to be sent via ID token. May be empty, but not null.
     * +
     */
    private List<String> translateAmrToResponse(List<String> internalList) {
        Set<String> result = new LinkedHashSet<>();
        for (String internalValue : internalList) {
            List<String> translatedToResponse = translateToResponse(internalValue);
            if (translatedToResponse.isEmpty()) {
                continue;
            }
            result.addAll(translatedToResponse);
        }
        return new ArrayList<>(result);
    }

    private List<String> translateToResponse(String internalValue) {
        List<String> result = Collections.EMPTY_LIST;
        AuthenticationMethodNameTranslator authenticationMethodNameTranslator = OAuth2ServiceComponentHolder
                .getAuthenticationMethodNameTranslator();
        if (authenticationMethodNameTranslator != null) {
            Set<String> externalAmrSet = authenticationMethodNameTranslator
                    .translateToExternalAmr(internalValue, INBOUND_AUTH2_TYPE);
            // When AMR mapping is not available.
            if (externalAmrSet == null || externalAmrSet.isEmpty()) {
                if (log.isDebugEnabled()) {
                    log.debug("There was no mapping found to translate AMR from internal to external URI. Internal " +
                            "Method Reference : " + internalValue);
                }
                result = new ArrayList<>();
                result.add(internalValue);
            } else if (externalAmrSet.contains(String.valueOf(Character.MIN_VALUE))) {
                // Authentication Method needs to be hidden from the ID Token.
                return Collections.emptyList();
            } else {
                result = new ArrayList<>(externalAmrSet);
            }
        }
        return result;
    }

    /**
     * Set user's tenant domain and userstore domain to the id_token's realm claim.
     *
     * @param authorizedUser authenticated user.
     * @param jwtClaimsSetBuilder JWT claim set builder.
     */
    private void setUserRealm(AuthenticatedUser authorizedUser, JWTClaimsSet.Builder
            jwtClaimsSetBuilder) {

        String tenantDomain = authorizedUser.getTenantDomain();
        String userstoreDomain = authorizedUser.getUserStoreDomain();
        Map<String, String> realm = new HashMap<>();
        if (OAuthServerConfiguration.getInstance().isAddTenantDomainToIdTokenEnabled() && StringUtils.isNotBlank
                (tenantDomain)) {
            realm.put(OAuthConstants.OIDCClaims.TENANT, tenantDomain);
        }
        if (OAuthServerConfiguration.getInstance().isAddUserstoreDomainToIdTokenEnabled() && StringUtils.isNotBlank
                (userstoreDomain)) {
            realm.put(OAuthConstants.OIDCClaims.USERSTORE, userstoreDomain);
        }
        if (realm.size() > 0) {
            if (log.isDebugEnabled()) {
                log.debug("Setting authorized user tenant domain : " + tenantDomain + " and userstore domain : " +
                        userstoreDomain + " to the 'realm' claim of id_token for the user : " + authorizedUser
                        .getLoggableUserId());
            }
            jwtClaimsSetBuilder.claim(OAuthConstants.OIDCClaims.REALM, realm);
        }
    }

    /**
     * Retrieves IDP session key using an Authorization Grant Cache Entry. This method is used in the Authorization Code
     * flow.
     *
     * @param authzGrantCacheEntry      Authorization Grant Cache Entry.
     * @return                          IDP Session Key.
     * @throws IdentityOAuth2Exception  Error if IDP Session Key is not available.
     */
    private String getIdpSessionKey(AuthorizationGrantCacheEntry authzGrantCacheEntry) throws IdentityOAuth2Exception {

        String idpSessionKey = authzGrantCacheEntry.getSessionContextIdentifier();
        if (idpSessionKey == null) {
            throw new IdentityOAuth2Exception("Session context identifier not available in the Authorization " +
                    "Grant cache. Session identifier is a required claim to be included in the id_token when " +
                    "the Session Extender endpoint is enabled.");
        }
        return idpSessionKey;
    }

    /**
     * Retrieves IDP session key using a Request Message Context. This method is used in the Implicit/Hybrid flows.
     *
     * @param authzReqMessageContext    Request Message Context.
     * @return                          IDP Session Key.
     * @throws IdentityOAuth2Exception  Error if IDP Session Key is not available.
     */
    private String getIdpSessionKey(OAuthAuthzReqMessageContext authzReqMessageContext) throws IdentityOAuth2Exception {

        String idpSessionKey = authzReqMessageContext.getAuthorizationReqDTO().getIdpSessionIdentifier();
        if (idpSessionKey == null) {
            throw new IdentityOAuth2Exception("Session context identifier not available in the Authorization " +
                    "Request Message context. Session identifier is a required claim to be included in the " +
                    "id_token when the Session Extender endpoint is enabled.");
        }
        return idpSessionKey;
    }

    /**
     * Retrieves IDP session key using an Access Token. This method is used in the Refresh Grant flow.
     * This method will return null for the backchannel grant types (e.g. Password Grant) as no session
     * will be involved in the said flow.
     *
     * @param accessToken   Access Token.
     * @return              IDP Session Key.
     */
    private String getIdpSessionKey(String accessToken) {

        String idpSessionKey = null;

        AuthorizationGrantCacheEntry authzGrantCacheEntry = getAuthorizationGrantCacheEntryFromToken(accessToken);
        if (authzGrantCacheEntry != null) {
            idpSessionKey = authzGrantCacheEntry.getSessionContextIdentifier();
        }
        // Not breaking the flow if the idpSessionKey is null as there could be other grant types that create
        // an Authorization Grant Cache entry against an access token but without a session.
        if (idpSessionKey == null && log.isDebugEnabled()) {
            log.debug("Session context identifier not available when retrieving using the access token.");
        }
        return idpSessionKey;
    }

    /**
     * Check the requirement of having a configured public certificate or JWKS in SP and throw an exception with an
     * error message if the public certificate or JWKS in SP is not configured.
     *
     * @param clientId     Client ID of the service provider.
     * @param tenantDomain Tenant domain of the service provider.
     * @throws IdentityOAuth2Exception Error when a JWKS endpoint or the certificate is not configured.
     */
    private void checkIfPublicCertConfiguredForEncryption(String clientId, String tenantDomain)
            throws IdentityOAuth2Exception {

        try {
            if (StringUtils.isBlank(OAuth2Util.getSPJwksUrl(clientId, tenantDomain))) {
                if (log.isDebugEnabled()) {
                    log.debug(String.format("Jwks uri is not configured for the service provider associated with " +
                            "client_id: %s , Checking for x509 certificate.", clientId));
                }
                OAuth2Util.getX509CertOfOAuthApp(clientId, tenantDomain);
            }
        } catch (IdentityOAuth2Exception e) {
            throw new IdentityOAuth2Exception("Cannot encrypt the ID token as the service Provider with client_id: "
                    + clientId + " of tenantDomain: " + tenantDomain + " does not have a public certificate or a " +
                    "JWKS endpoint configured.", e);
        }
    }


    /**
     * Create a new IDTokenDTO instance.
     *
     * @param authzReqMessageContext OAuthAuthzReqMessageContext
     * @param idTokenJwtClaimSetBuilder JWTClaimsSet.Builder
     * @param audience List<String>
     * @param expiresIn long
     * @param oidcClaimSet Map<String, Object>
     * @return IDTokenDTO
     */
    private IDTokenDTO getIDTokenDTO(OAuthAuthzReqMessageContext authzReqMessageContext,
                                     JWTClaimsSet.Builder idTokenJwtClaimSetBuilder,
                                     List<String> audience,
                                     long expiresIn,
                                     Map<String, Object> oidcClaimSet) {

        IDTokenDTO idTokenDTO = new IDTokenDTO();
        idTokenDTO.setIdTokenClaimsSet(idTokenJwtClaimSetBuilder.build());
        idTokenDTO.setAudience(audience);
        idTokenDTO.setExpiresIn(expiresIn);
        idTokenDTO.setCustomOIDCClaims(new HashMap<>(oidcClaimSet));
        return idTokenDTO;
    }

    /**
     * Get IDTokenDTO either from the pre issue ID token action execution if the action was executed during a previous
     * flow or create a new instance.
     *
     * @param tokenReqMessageContext OAuthTokenReqMessageContext
     * @param idTokenJwtClaimSetBuilder JWTClaimsSet.Builder
     * @param audience List<String>
     * @param expiresIn long
     * @param oidcClaimSet Map<String, Object>
     * @return IDTokenDTO
     */
    private IDTokenDTO getIDTokenDTO(OAuthTokenReqMessageContext tokenReqMessageContext,
                                     JWTClaimsSet.Builder idTokenJwtClaimSetBuilder,
                                     List<String> audience,
                                     long expiresIn,
                                     Map<String, Object> oidcClaimSet) {

        if (tokenReqMessageContext.isPreIssueIDTokenActionsExecuted()) {
            IDTokenDTO idTokenDTO = tokenReqMessageContext.getPreIssueIDTokenActionDTO();
            idTokenDTO.setIdTokenClaimsSet(idTokenJwtClaimSetBuilder.build());
            return idTokenDTO;
        }
        IDTokenDTO idTokenDTO = new IDTokenDTO();
        idTokenDTO.setIdTokenClaimsSet(idTokenJwtClaimSetBuilder.build());
        idTokenDTO.setAudience(audience);
        idTokenDTO.setExpiresIn(expiresIn);
        idTokenDTO.setCustomOIDCClaims(new HashMap<>(oidcClaimSet));
        return idTokenDTO;
    }

    /**
     * Build JWT claim set after executing pre issue ID token actions.
     *
     * @param idTokenDTO IDTokenDTO
     * @return JWTClaimsSet
     */
    private JWTClaimsSet buildJWTClaimSetIdTokenDto(IDTokenDTO idTokenDTO) {

        JWTClaimsSet initialJWTClaimsSet = idTokenDTO.getIdTokenClaimsSet();
        Map<String, Object> customOIDCClaims = idTokenDTO.getCustomOIDCClaims();
        JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder(initialJWTClaimsSet);
        customOIDCClaims.forEach(jwtClaimsSetBuilder::claim);

        long currentTimeInMillis = Calendar.getInstance().getTimeInMillis();
        jwtClaimsSetBuilder.issueTime(new Date(currentTimeInMillis));
        jwtClaimsSetBuilder.notBeforeTime(new Date(currentTimeInMillis));
        jwtClaimsSetBuilder.audience(idTokenDTO.getAudience());
        jwtClaimsSetBuilder.expirationTime(getIdTokenExpiryInMillis(currentTimeInMillis, idTokenDTO.getExpiresIn()));
        return jwtClaimsSetBuilder.build();
    }

    /**
     * Execute pre issue ID token actions.
     *
     * @param tokenReqMessageContext OAuthTokenReqMessageContext
     * @return ActionExecutionStatus
     * @throws IdentityOAuth2Exception IdentityOAuth2Exception if an error occurs
     */
    private ActionExecutionStatus<?> executePreIssueIdTokenActions(OAuthTokenReqMessageContext tokenReqMessageContext,
                                                                   IDTokenDTO idTokenDTO, OAuthAppDO oAuthAppDO)
            throws IdentityOAuth2Exception {

        ActionExecutionStatus<?> executionStatus = null;

        FlowContext flowContext = FlowContext.create()
                .add(TOKEN_REQUEST_MESSAGE_CONTEXT, tokenReqMessageContext)
                .add(ID_TOKEN_DTO, idTokenDTO)
                .add(REQUEST_TYPE, REQUEST_TYPE_TOKEN);

        try {
            String tenantDomain = IdentityTenantUtil.getTenantDomain(IdentityTenantUtil.getLoginTenantId());
            // Selecting the action execution tenant domain based on the application's issuer organization.
            if (StringUtils.isNotEmpty(PrivilegedCarbonContext.getThreadLocalCarbonContext().
                    getApplicationResidentOrganizationId())) {
                if (StringUtils.isNotEmpty(oAuthAppDO.getIssuerOrg())) {
                    tenantDomain = OAuth2ServiceComponentHolder.getInstance().getOrganizationManager().
                            resolveTenantDomain(oAuthAppDO.getIssuerOrg());
                }
            }
            executionStatus = OAuthComponentServiceHolder.getInstance().getActionExecutorService()
                    .execute(ActionType.PRE_ISSUE_ID_TOKEN, flowContext, tenantDomain);

            if (log.isDebugEnabled()) {
                log.debug(String.format(
                        "Invoked pre issue ID token action for clientID: %s grant types: %s. Status: %s",
                        tokenReqMessageContext.getOauth2AccessTokenReqDTO().getClientId(),
                        tokenReqMessageContext.getOauth2AccessTokenReqDTO().getGrantType(),
                        Optional.ofNullable(executionStatus).isPresent() ? executionStatus.getStatus() : "NA"));
            }
        } catch (ActionExecutionException e) {
            String errorMsg = "Error occurred while executing pre issue ID token actions for client_id: "
                    + tokenReqMessageContext.getOauth2AccessTokenReqDTO().getClientId();
            throw new IdentityOAuth2Exception(errorMsg, e);

        } catch (OrganizationManagementException e) {
            String errorMsg = "Error occurred while resolving tenant domain from organization id while executing " +
                    "pre issue ID token actions for client_id: "
                    + tokenReqMessageContext.getOauth2AccessTokenReqDTO().getClientId();
            throw new IdentityOAuth2Exception(errorMsg, e);
        }
        return executionStatus;
    }

    /**
     * Execute pre issue ID token actions.
     *
     * @param authzReqMessageContext OAuthAuthzReqMessageContext
     * @return ActionExecutionStatus
     * @throws IdentityOAuth2Exception IdentityOAuth2Exception if an error occurs
     */
    private ActionExecutionStatus<?> executePreIssueIdTokenActions(OAuthAuthzReqMessageContext authzReqMessageContext,
                                                                   IDTokenDTO idTokenDTO)
            throws IdentityOAuth2Exception {

        ActionExecutionStatus<?> executionStatus = null;

        FlowContext flowContext = FlowContext.create()
                .add(AUTHZ_REQUEST_MESSAGE_CONTEXT, authzReqMessageContext)
                .add(ID_TOKEN_DTO, idTokenDTO)
                .add(REQUEST_TYPE, REQUEST_TYPE_AUTHZ);

        try {
            executionStatus = OAuthComponentServiceHolder.getInstance().getActionExecutorService()
                    .execute(ActionType.PRE_ISSUE_ID_TOKEN, flowContext,
                            IdentityTenantUtil.getTenantDomain(IdentityTenantUtil.getLoginTenantId()));

            if (log.isDebugEnabled()) {
                log.debug(String.format(
                        "Invoked pre issue ID token action for clientID: %s grant types: %s. Status: %s",
                        authzReqMessageContext.getAuthorizationReqDTO().getConsumerKey(),
                        authzReqMessageContext.getAuthorizationReqDTO().getResponseType(),
                        Optional.ofNullable(executionStatus).isPresent() ? executionStatus.getStatus() : "NA"));
            }
        } catch (ActionExecutionException e) {
            String errorMsg = "Error occurred while executing pre issue ID token actions for client_id: "
                    + authzReqMessageContext.getAuthorizationReqDTO().getConsumerKey();
            throw new IdentityOAuth2Exception(errorMsg, e);

        }
        return executionStatus;
    }

    /**
     * Check whether to execute pre issue ID token actions.
     *
     * @param tokenReqMessageContext OAuthTokenReqMessageContext
     * @return true if pre issue ID token actions execution is enabled
     * @throws IdentityOAuth2Exception Error when checking action execution is failed
     */
    private boolean checkExecutePreIssueIdTokensActions(OAuthTokenReqMessageContext tokenReqMessageContext)
            throws IdentityOAuth2Exception {

        String tenantDomain = tokenReqMessageContext.getOauth2AccessTokenReqDTO().getTenantDomain();
        String clientId = tokenReqMessageContext.getOauth2AccessTokenReqDTO().getClientId();
        String grantType = tokenReqMessageContext.getOauth2AccessTokenReqDTO().getGrantType();
        // PreIssue ID token actions are only executed for the following grant types.
        boolean isGrantTypeAllowed = (OAuthConstants.GrantTypes.AUTHORIZATION_CODE.equals(grantType) ||
                OAuthConstants.GrantTypes.PASSWORD.equals(grantType) ||
                OAuthConstants.GrantTypes.REFRESH_TOKEN.equals(grantType) ||
                OAuthConstants.GrantTypes.DEVICE_CODE_URN.equals(grantType) ||
                OAuthConstants.GrantTypes.ORGANIZATION_SWITCH.equals(grantType));

        // Pre-issue token action invocation is enabled at server level.
        // For the System applications, pre issue ID token actions will not be executed.
        // Fragment apps are used for internal authentication purposes(B2B scenarios) hence action execution is skipped.
        return !isSystemApplication(tenantDomain, clientId) && isGrantTypeAllowed &&
                OAuthComponentServiceHolder.getInstance().getActionExecutorService()
                        .isExecutionEnabled(ActionType.PRE_ISSUE_ID_TOKEN) &&
                !OAuth2Util.isFragmentApp(clientId, tenantDomain);
    }

    /**
     * Check whether the given application is a system application.
     *
     * @param tenantDomain Tenant domain of the application.
     * @param clientId     Client ID of the application.
     * @return true if the application is a system application.
     * @throws IdentityOAuth2Exception Error when checking system application fails.
     */
    private boolean isSystemApplication(String tenantDomain, String clientId) throws IdentityOAuth2Exception {

        return IdentityTenantUtil.isSystemApplication(tenantDomain, clientId);
    }

    /**
     * Check whether to execute pre issue ID token actions.
     *
     * @param authzReqMessageContext OAuthAuthzReqMessageContext
     * @return true if pre issue ID token actions execution is enabled
     * @throws IdentityOAuth2Exception Error when checking action execution is failed
     */
    private boolean checkExecutePreIssueIdTokensActions(OAuthAuthzReqMessageContext authzReqMessageContext)
            throws IdentityOAuth2Exception {

        String tenantDomain = authzReqMessageContext.getAuthorizationReqDTO().getTenantDomain();
        String clientId = authzReqMessageContext.getAuthorizationReqDTO().getConsumerKey();
        String responseType = authzReqMessageContext.getAuthorizationReqDTO().getResponseType();

        // Implicit flow(response type id_token token) is not supported.
        boolean isResponseTypeAllowed = OAuthConstants.CODE_IDTOKEN.equals(responseType) ||
                OAuthConstants.CODE_IDTOKEN_TOKEN.equals(responseType);
        // Pre-issue token action invocation is enabled at server level.
        // For the System applications(Console, MyAccount), pre issue ID token actions will not be executed.
        // Fragment apps are used for internal authentication purposes(B2B scenarios) hence action execution is skipped.
        return !isSystemApplication(tenantDomain, clientId) &&
                isResponseTypeAllowed && OAuthComponentServiceHolder.getInstance().getActionExecutorService()
                        .isExecutionEnabled(ActionType.PRE_ISSUE_ID_TOKEN) &&
                !OAuth2Util.isFragmentApp(clientId, tenantDomain);
    }

    /**
     * Handle failure or error response from action execution.
     *
     * @param executionStatus Action execution status
     * @throws IdentityOAuth2Exception IdentityOAuth2Exception
     */
    private void handleFailureOrError(ActionExecutionStatus<?> executionStatus)
            throws IdentityOAuth2Exception {

        if (executionStatus.getStatus() == ActionExecutionStatus.Status.FAILED) {
            Failure failureResponse = (Failure) executionStatus.getResponse();
            throw new IdentityOAuth2ClientException(failureResponse.getFailureReason(),
                    failureResponse.getFailureDescription());
        } else if (executionStatus.getStatus() == ActionExecutionStatus.Status.ERROR) {
            Error errorResponse = (Error) executionStatus.getResponse();
            throw new IdentityOAuth2Exception(errorResponse.getErrorMessage(),
                    errorResponse.getErrorDescription());
        }
    }
}
