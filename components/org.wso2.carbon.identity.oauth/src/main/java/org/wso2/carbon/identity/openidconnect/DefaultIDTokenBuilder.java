/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.carbon.identity.openidconnect;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticationMethodNameTranslator;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ClaimConfig;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IDTokenValidationFailureException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.internal.OpenIDConnectServiceComponentHolder;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.apache.commons.lang.StringUtils.isNotBlank;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCClaims.AUTH_TIME;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCClaims.AZP;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCClaims.NONCE;

/**
 * Default IDToken generator for the OpenID Connect Implementation.
 * This IDToken Generator utilizes the Nimbus SDK to build the IDToken.
 */
public class DefaultIDTokenBuilder implements org.wso2.carbon.identity.openidconnect.IDTokenBuilder {

    private static final String AUTHORIZATION_CODE = "AuthorizationCode";
    private static final String INBOUND_AUTH2_TYPE = "oauth2";

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
        String idTokenIssuer = OAuth2Util.getIdTokenIssuer(spTenantDomain);
        String accessToken = tokenRespDTO.getAccessToken();

        // Initialize OAuthAppDO using the client ID.
        OAuthAppDO oAuthAppDO;
        try {
            oAuthAppDO = OAuth2Util.getAppInformationByClientId(clientId);
        } catch (InvalidOAuthClientException e) {
            String error = "Error occurred while getting app information for client_id: " + clientId;
            throw new IdentityOAuth2Exception(error, e);
        }

        long idTokenValidityInMillis = getIDTokenExpiryInMillis(oAuthAppDO);
        long currentTimeInMillis = Calendar.getInstance().getTimeInMillis();

        AuthenticatedUser authorizedUser = tokenReqMsgCtxt.getAuthorizedUser();
        String subjectClaim = getSubjectClaim(tokenReqMsgCtxt, tokenRespDTO, clientId, spTenantDomain, authorizedUser);

        String nonceValue = null;
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
            }
        } else {
            amrValues = tokenReqMsgCtxt.getOauth2AccessTokenReqDTO().getAuthenticationMethodReferences();
        }

        if (log.isDebugEnabled()) {
            log.debug(buildDebugMessage(idTokenIssuer, subjectClaim, nonceValue, idTokenValidityInMillis,
                    currentTimeInMillis));
        }

        List<String> audience = OAuth2Util.getOIDCAudience(clientId, oAuthAppDO);

        JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
        jwtClaimsSetBuilder.issuer(idTokenIssuer);
        jwtClaimsSetBuilder.audience(audience);
        jwtClaimsSetBuilder.claim(AZP, clientId);
        jwtClaimsSetBuilder.expirationTime(getIdTokenExpiryInMillis(idTokenValidityInMillis, currentTimeInMillis));
        jwtClaimsSetBuilder.issueTime(new Date(currentTimeInMillis));
        jwtClaimsSetBuilder.notBeforeTime(new Date(currentTimeInMillis));
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
        setUserRealm(authorizedUser, jwtClaimsSetBuilder);
        setAdditionalClaims(tokenReqMsgCtxt, tokenRespDTO, jwtClaimsSetBuilder);

        tokenReqMsgCtxt.addProperty(OAuthConstants.ACCESS_TOKEN, accessToken);
        tokenReqMsgCtxt.addProperty(MultitenantConstants.TENANT_DOMAIN, getSpTenantDomain(tokenReqMsgCtxt));
        jwtClaimsSetBuilder.subject(subjectClaim);
        JWTClaimsSet jwtClaimsSet = handleOIDCCustomClaims(tokenReqMsgCtxt, jwtClaimsSetBuilder);

        if (isInvalidToken(jwtClaimsSet)) {
            throw new IDTokenValidationFailureException("Error while validating ID Token token for required claims");
        }

        if (isUnsignedIDToken()) {
            return new PlainJWT(jwtClaimsSet).serialize();
        }


        return getIDToken(clientId, spTenantDomain, jwtClaimsSet, oAuthAppDO, getSigningTenantDomain(tokenReqMsgCtxt));
    }

    @Override
    public String buildIDToken(OAuthAuthzReqMessageContext authzReqMessageContext,
                               OAuth2AuthorizeRespDTO tokenRespDTO) throws IdentityOAuth2Exception {

        String accessToken = tokenRespDTO.getAccessToken();
        String clientId = authzReqMessageContext.getAuthorizationReqDTO().getConsumerKey();
        String spTenantDomain = getSpTenantDomain(authzReqMessageContext);
        String issuer = OAuth2Util.getIdTokenIssuer(spTenantDomain);

        // Get subject from Authenticated Subject Identifier
        AuthenticatedUser authorizedUser = authzReqMessageContext.getAuthorizationReqDTO().getUser();
        String subject =
                getSubjectClaim(authzReqMessageContext, tokenRespDTO, clientId, spTenantDomain, authorizedUser);

        String nonceValue = authzReqMessageContext.getAuthorizationReqDTO().getNonce();
        String acrValue = authzReqMessageContext.getAuthorizationReqDTO().getSelectedAcr();
        List<String> amrValues = Collections.emptyList(); //TODO:

        // Initialize OAuthAppDO using the client ID.
        OAuthAppDO oAuthAppDO;
        try {
            oAuthAppDO = OAuth2Util.getAppInformationByClientId(clientId);
        } catch (InvalidOAuthClientException e) {
            String error = "Error occurred while getting app information for client_id: " + clientId;
            throw new IdentityOAuth2Exception(error, e);
        }

        String[] amrValueArray = (String[])(authzReqMessageContext.getAuthorizationReqDTO().getProperty(OAuthConstants
                .AMR));
        if (ArrayUtils.isNotEmpty(amrValueArray)) {
            amrValues = Arrays.asList(amrValueArray);
        }
        long idTokenLifeTimeInMillis = getIDTokenExpiryInMillis(oAuthAppDO);
        long currentTimeInMillis = Calendar.getInstance().getTimeInMillis();

        if (log.isDebugEnabled()) {
            log.debug(buildDebugMessage(issuer, subject, nonceValue, idTokenLifeTimeInMillis, currentTimeInMillis));
        }

        JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
        jwtClaimsSetBuilder.issuer(issuer);

        // Set the audience
        List<String> audience = OAuth2Util.getOIDCAudience(clientId, oAuthAppDO);
        jwtClaimsSetBuilder.audience(audience);

        jwtClaimsSetBuilder.claim(AZP, clientId);
        jwtClaimsSetBuilder.expirationTime(getIdTokenExpiryInMillis(idTokenLifeTimeInMillis, currentTimeInMillis));
        jwtClaimsSetBuilder.issueTime(new Date(currentTimeInMillis));

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
        setUserRealm(authorizedUser, jwtClaimsSetBuilder);
        setAdditionalClaims(authzReqMessageContext, tokenRespDTO, jwtClaimsSetBuilder);

        authzReqMessageContext.addProperty(OAuthConstants.ACCESS_TOKEN, accessToken);
        authzReqMessageContext.addProperty(MultitenantConstants.TENANT_DOMAIN, getSpTenantDomain(authzReqMessageContext));
        jwtClaimsSetBuilder.subject(subject);
        JWTClaimsSet jwtClaimsSet = handleCustomOIDCClaims(authzReqMessageContext, jwtClaimsSetBuilder);

        if (isUnsignedIDToken()) {
            return new PlainJWT(jwtClaimsSet).serialize();
        }

        return getIDToken(clientId, spTenantDomain, jwtClaimsSet, oAuthAppDO,
                getSigningTenantDomain(authzReqMessageContext));
    }

    private String getIDToken(String clientId, String spTenantDomain, JWTClaimsSet jwtClaimsSet, OAuthAppDO oAuthAppDO,
                              String signingTenantDomain) throws IdentityOAuth2Exception {

        if (oAuthAppDO.isIdTokenEncryptionEnabled()) {
            setupEncryptionAlgorithms(oAuthAppDO, clientId);
            return OAuth2Util.encryptJWT(jwtClaimsSet, encryptionAlgorithm, encryptionMethod, spTenantDomain,
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
        String accessToken = tokenRespDTO.getAccessToken();
        String subjectClaim = OIDCClaimUtil.getSubjectClaimCachedAgainstAccessToken(accessToken);
        if (isNotBlank(subjectClaim)) {
            if (log.isDebugEnabled()) {
                if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.USER_CLAIMS)) {
                    log.debug("Subject claim cached against the access token found for user: " + authorizedUser);
                } else {
                    log.debug("Subject claim: " + subjectClaim + " cached against the access token found for user: " +
                            authorizedUser);
                }
            }
            return subjectClaim;
        }
        return getSubjectClaim(clientId, spTenantDomain, authorizedUser);
    }

    protected String getSubjectClaim(OAuthAuthzReqMessageContext authzReqMessageContext,
                                     OAuth2AuthorizeRespDTO authorizeRespDTO,
                                     String clientId,
                                     String spTenantDomain,
                                     AuthenticatedUser authorizedUser) throws IdentityOAuth2Exception {
        String accessToken = authorizeRespDTO.getAccessToken();
        String subjectClaim = OIDCClaimUtil.getSubjectClaimCachedAgainstAccessToken(accessToken);
        if (isNotBlank(subjectClaim)) {
            if (log.isDebugEnabled()) {
                if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.USER_CLAIMS)) {
                    log.debug("Subject claim cached against the authz code found for user: " + authorizedUser);
                } else {
                    log.debug("Subject claim: " + subjectClaim + " cached against the authz code found for user: " +
                            authorizedUser);
                }
            }
            return subjectClaim;
        }
        return getSubjectClaim(clientId, spTenantDomain, authorizedUser);
    }

    private String getSubjectClaim(String clientId,
                                   String spTenantDomain,
                                   AuthenticatedUser authorizedUser) throws IdentityOAuth2Exception {
        String subjectClaim;
        if (isLocalUser(authorizedUser)) {
            // If the user is local then we need to find the subject claim of the user defined in SP configs and
            // append userStoreDomain/tenantDomain as configured
            ServiceProvider serviceProvider = getServiceProvider(spTenantDomain, clientId);
            if (serviceProvider == null) {
                throw new IdentityOAuth2Exception("Cannot find an service provider for client_id: " + clientId + " " +
                        "in tenantDomain: " + spTenantDomain);
            }
            subjectClaim = getSubjectClaimForLocalUser(serviceProvider, authorizedUser);
            if (log.isDebugEnabled()) {
                log.debug("Subject claim: " + subjectClaim + " set for local user: " + authorizedUser + " for " +
                        "application: " + clientId + " of tenantDomain: " + spTenantDomain);
            }
        } else {
            subjectClaim = authorizedUser.getAuthenticatedSubjectIdentifier();
            if (log.isDebugEnabled()) {
                log.debug("Subject claim: " + subjectClaim + " set for federated user: " + authorizedUser + " for " +
                        "application: " + clientId + " of tenantDomain: " + spTenantDomain);
            }
        }
        return subjectClaim;
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

    private boolean isIDTokenSigned() {
        return !JWSAlgorithm.NONE.getName().equals(signatureAlgorithm.getName());
    }

    private String getAuthorizationCode(OAuthTokenReqMessageContext tokenReqMsgCtxt) {
        return (String) tokenReqMsgCtxt.getProperty(AUTHORIZATION_CODE);
    }

    private boolean isLocalUser(AuthenticatedUser authorizedUser) {
        return !authorizedUser.isFederatedUser();
    }

    private String getSpTenantDomain(OAuthTokenReqMessageContext tokReqMsgCtx) {
        return tokReqMsgCtx.getOauth2AccessTokenReqDTO().getTenantDomain();
    }

    private JWTClaimsSet handleOIDCCustomClaims(OAuthTokenReqMessageContext tokReqMsgCtx, JWTClaimsSet.Builder
            jwtClaimsSetBuilder) {
        CustomClaimsCallbackHandler claimsCallBackHandler =
                OAuthServerConfiguration.getInstance().getOpenIDConnectCustomClaimsCallbackHandler();
        return claimsCallBackHandler.handleCustomClaims(jwtClaimsSetBuilder, tokReqMsgCtx);
    }

    private String getSubjectClaimForLocalUser(ServiceProvider serviceProvider,
                                               AuthenticatedUser authorizedUser) throws IdentityOAuth2Exception {
        String subject;
        String username = authorizedUser.getUserName();
        String userStoreDomain = authorizedUser.getUserStoreDomain();
        String userTenantDomain = authorizedUser.getTenantDomain();

        String subjectClaimUri = getSubjectClaimUriInLocalDialect(serviceProvider);
        if (StringUtils.isNotBlank(subjectClaimUri)) {
            String fullQualifiedUsername = authorizedUser.toFullQualifiedUsername();
            try {
                subject = getSubjectClaimFromUserStore(subjectClaimUri, authorizedUser);
                if (StringUtils.isBlank(subject)) {
                    // Set username as the subject claim since we have no other option
                    subject = username;
                    log.warn("Cannot find subject claim: " + subjectClaimUri + " for user:" + fullQualifiedUsername
                            + ". Defaulting to username: " + subject + " as the subject identifier.");
                }
                // Get the subject claim in the correct format (ie. tenantDomain or userStoreDomain appended)
                subject = getFormattedSubjectClaim(serviceProvider, subject, userStoreDomain, userTenantDomain);
            } catch (IdentityException e) {
                String error = "Error occurred while getting user claim for user: " + authorizedUser + ", claim: " +
                        subjectClaimUri;
                throw new IdentityOAuth2Exception(error, e);
            } catch (UserStoreException e) {
                String error = "Error occurred while getting subject claim: " + subjectClaimUri + " for user: "
                        + fullQualifiedUsername;
                throw new IdentityOAuth2Exception(error, e);
            }
        } else {
            subject = getFormattedSubjectClaim(serviceProvider, username, userStoreDomain, userTenantDomain);
            if (log.isDebugEnabled()) {
                log.debug("No subject claim defined for service provider: " + serviceProvider.getApplicationName()
                        + ". Using username as the subject claim.");
            }
        }
        return subject;
    }

    private String getSubjectClaimFromUserStore(String subjectClaimUri, AuthenticatedUser authenticatedUser)
            throws UserStoreException, IdentityException {

        UserStoreManager userStoreManager = IdentityTenantUtil
                .getRealm(authenticatedUser.getTenantDomain(), authenticatedUser.toFullQualifiedUsername())
                .getUserStoreManager();

        return userStoreManager
                .getSecondaryUserStoreManager(authenticatedUser.getUserStoreDomain())
                .getUserClaimValue(authenticatedUser.getUserName(), subjectClaimUri, null);
    }

    private String getSubjectClaimUriInLocalDialect(ServiceProvider serviceProvider) {
        String subjectClaimUri = serviceProvider.getLocalAndOutBoundAuthenticationConfig().getSubjectClaimUri();
        if (log.isDebugEnabled()) {
            if (isNotBlank(subjectClaimUri)) {
                log.debug(subjectClaimUri + " is defined as subject claim for service provider: " +
                        serviceProvider.getApplicationName());
            } else {
                log.debug("No subject claim defined for service provider: " + serviceProvider.getApplicationName());
            }
        }
        // Get the local subject claim URI, if subject claim was a SP mapped one
        return getSubjectClaimUriInLocalDialect(serviceProvider, subjectClaimUri);
    }

    private String getFormattedSubjectClaim(ServiceProvider serviceProvider,
                                            String subjectClaimValue,
                                            String userStoreDomain,
                                            String tenantDomain) {

        boolean appendUserStoreDomainToSubjectClaim = serviceProvider.getLocalAndOutBoundAuthenticationConfig()
                .isUseUserstoreDomainInLocalSubjectIdentifier();

        boolean appendTenantDomainToSubjectClaim = serviceProvider.getLocalAndOutBoundAuthenticationConfig()
                .isUseTenantDomainInLocalSubjectIdentifier();

        if (appendTenantDomainToSubjectClaim) {
            subjectClaimValue = UserCoreUtil.addTenantDomainToEntry(subjectClaimValue, tenantDomain);
        }
        if (appendUserStoreDomainToSubjectClaim) {
            subjectClaimValue = IdentityUtil.addDomainToName(subjectClaimValue, userStoreDomain);
        }

        return subjectClaimValue;
    }

    private String getSigningTenantDomain(OAuthTokenReqMessageContext tokReqMsgCtx) {
        boolean isJWTSignedWithSPKey = OAuthServerConfiguration.getInstance().isJWTSignedWithSPKey();
        if (isJWTSignedWithSPKey) {
            return (String) tokReqMsgCtx.getProperty(MultitenantConstants.TENANT_DOMAIN);
        } else {
            return tokReqMsgCtx.getAuthorizedUser().getTenantDomain();
        }
    }

    private String getSubjectClaimUriInLocalDialect(ServiceProvider serviceProvider, String subjectClaimUri) {
        if (isNotBlank(subjectClaimUri)) {
            ClaimConfig claimConfig = serviceProvider.getClaimConfig();
            if (claimConfig != null) {
                boolean isLocalClaimDialect = claimConfig.isLocalClaimDialect();
                ClaimMapping[] claimMappings = claimConfig.getClaimMappings();
                if (!isLocalClaimDialect && ArrayUtils.isNotEmpty(claimMappings)) {
                    for (ClaimMapping claimMapping : claimMappings) {
                        if (StringUtils.equals(claimMapping.getRemoteClaim().getClaimUri(), subjectClaimUri)) {
                            return claimMapping.getLocalClaim().getClaimUri();
                        }
                    }
                }
            }
        }
        // This means the original subjectClaimUri passed was the subject claim URI.
        return subjectClaimUri;
    }

    private ServiceProvider getServiceProvider(String spTenantDomain,
                                               String clientId) throws IdentityOAuth2Exception {
        ApplicationManagementService applicationMgtService = OAuth2ServiceComponentHolder.getApplicationMgtService();
        try {
            String spName =
                    applicationMgtService
                            .getServiceProviderNameByClientId(clientId, INBOUND_AUTH2_TYPE, spTenantDomain);
            return applicationMgtService.getApplicationExcludingFileBasedSPs(spName, spTenantDomain);
        } catch (IdentityApplicationManagementException e) {
            throw new IdentityOAuth2Exception("Error while getting service provider information for client_id: "
                    + clientId + " tenantDomain: " + spTenantDomain, e);
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

    private boolean isAccessTokenHashApplicable(String responseType) {
        // At_hash is generated on an access token. Therefore check whether the response type returns an access_token.
        // id_token and none response types don't return and access token.
        return !OAuthConstants.ID_TOKEN.equalsIgnoreCase(responseType) &&
                !OAuthConstants.NONE.equalsIgnoreCase(responseType);
    }

    private Date getIdTokenExpiryInMillis(long currentTimeInMillis, long lifetimeInMillis) {
        return new Date(currentTimeInMillis + lifetimeInMillis);
    }

    private JWTClaimsSet handleCustomOIDCClaims(OAuthAuthzReqMessageContext request, JWTClaimsSet.Builder jwtClaimsSetBuilder) {
        CustomClaimsCallbackHandler claimsCallBackHandler =
                OAuthServerConfiguration.getInstance().getOpenIDConnectCustomClaimsCallbackHandler();
        return claimsCallBackHandler.handleCustomClaims(jwtClaimsSetBuilder, request);
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
            log.error("ID token does not have required issuer claim");
            return false;
        }
        if (StringUtils.isBlank(jwtClaimsSet.getSubject())) {
            log.error("ID token does not have required subject claim");
            return false;
        }
        if (jwtClaimsSet.getAudience() == null) {
            log.error("ID token does not have required audience claim");
            return false;
        }
        if (jwtClaimsSet.getExpirationTime() == null) {
            log.error("ID token does not have required expiration time claim");
            return false;
        }
        if (jwtClaimsSet.getIssueTime() == null) {
            log.error("ID token does not have required issued time claim");
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

    /**
     * +     * Converts the internal representation to external (response) form.
     * +     * The resultant list will not have any duplicate values.
     * +     * @param internalList
     * +     * @return a list of amr values to be sent via ID token. May be empty, but not null.
     * +
     */
    private List<String> translateAmrToResponse(List<String> internalList) {
        Set<String> result = new HashSet<>();
        for (String internalValue : internalList) {
            result.addAll(translateToResponse(internalValue));
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
            if (externalAmrSet == null || externalAmrSet.isEmpty()) {
                if (log.isDebugEnabled()) {
                    log.debug("There was no mapping found to translate AMR from internal to external URI. Internal " +
                            "Method Reference : " + internalValue);
                }
                result = new ArrayList<>();
                result.add(internalValue);
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
                        .getUserName());
            }
            jwtClaimsSetBuilder.claim(OAuthConstants.OIDCClaims.REALM, realm);
        }
    }
}
