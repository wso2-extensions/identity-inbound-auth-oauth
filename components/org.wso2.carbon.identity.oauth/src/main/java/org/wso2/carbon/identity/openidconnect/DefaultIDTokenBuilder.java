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
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import org.apache.axiom.om.OMElement;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.Charsets;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ClaimConfig;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IDTokenValidationFailureException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import javax.xml.namespace.QName;

import static org.apache.commons.lang.StringUtils.isNotBlank;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCClaims.AT_HASH;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCClaims.AUTH_TIME;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCClaims.AZP;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCClaims.NONCE;

/**
 * Default IDToken generator for the OpenID Connect Implementation.
 * This IDToken Generator utilizes the Nimbus SDK to build the IDToken.
 */
public class DefaultIDTokenBuilder implements org.wso2.carbon.identity.openidconnect.IDTokenBuilder {
    private static final String SHA384 = "SHA-384";
    private static final String SHA512 = "SHA-512";
    private static final String AUTHORIZATION_CODE = "AuthorizationCode";
    private static final String INBOUND_AUTH2_TYPE = "oauth2";
    private static final String CONFIG_ELEM_OAUTH = "OAuth";
    private static final String OPENID_CONNECT = "OpenIDConnect";
    private static final String OPENID_CONNECT_AUDIENCES = "Audiences";
    private static final String OPENID_CONNECT_AUDIENCE = "Audience";
    private static final String OPENID_IDP_ENTITY_ID = "IdPEntityId";

    private static final Log log = LogFactory.getLog(DefaultIDTokenBuilder.class);
    private JWSAlgorithm signatureAlgorithm = null;

    public DefaultIDTokenBuilder() throws IdentityOAuth2Exception {
        //map signature algorithm from identity.xml to nimbus format, this is a one time configuration
        signatureAlgorithm = OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm(
                OAuthServerConfiguration.getInstance().getIdTokenSignatureAlgorithm());
    }

    @Override
    public String buildIDToken(OAuthTokenReqMessageContext tokenReqMsgCtxt,
                               OAuth2AccessTokenRespDTO tokenRespDTO) throws IdentityOAuth2Exception {

        String clientId = tokenReqMsgCtxt.getOauth2AccessTokenReqDTO().getClientId();
        String spTenantDomain = getSpTenantDomain(tokenReqMsgCtxt);
        String idTokenIssuer = getIdTokenIssuer(spTenantDomain);

        long idTokenValidityInMillis = getIDTokenExpiryInMillis();
        long currentTimeInMillis = Calendar.getInstance().getTimeInMillis();

        AuthenticatedUser authorizedUser = tokenReqMsgCtxt.getAuthorizedUser();
        String subjectClaim = getSubjectClaim(tokenReqMsgCtxt, tokenRespDTO, clientId, spTenantDomain, authorizedUser);

        String nonceValue = null;
        long authTime = 0;
        LinkedHashSet acrValue = new LinkedHashSet();

        // AuthorizationCode only available for authorization code grant type
        if (getAuthorizationCode(tokenReqMsgCtxt) != null) {
            AuthorizationGrantCacheEntry authzGrantCacheEntry = getAuthorizationGrantCacheEntry(tokenReqMsgCtxt);
            if (authzGrantCacheEntry != null) {
                nonceValue = authzGrantCacheEntry.getNonceValue();
                acrValue = authzGrantCacheEntry.getAcrValue();
                if (authzGrantCacheEntry.getEssentialClaims() != null) {
                    if (isEssentialClaim(authzGrantCacheEntry, AUTH_TIME)) {
                        authTime = authzGrantCacheEntry.getAuthTime();
                    }
                }
            }
        }

        String atHash = null;
        String accessToken = tokenRespDTO.getAccessToken();
        if (isIDTokenSigned() && isNotBlank(accessToken)) {
            atHash = getAtHash(accessToken);
        }

        if (log.isDebugEnabled()) {
            log.debug(buildDebugMessage(idTokenIssuer, subjectClaim, nonceValue, idTokenValidityInMillis, currentTimeInMillis));
        }

        List<String> audience = getOIDCAudience(clientId);

        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet();
        jwtClaimsSet.setIssuer(idTokenIssuer);
        jwtClaimsSet.setAudience(audience);
        jwtClaimsSet.setClaim(AZP, clientId);
        jwtClaimsSet.setExpirationTime(getIdTokenExpiryInMillis(idTokenValidityInMillis, currentTimeInMillis));
        jwtClaimsSet.setIssueTime(new Date(currentTimeInMillis));
        if (authTime != 0) {
            jwtClaimsSet.setClaim(AUTH_TIME, authTime / 1000);
        }
        if (atHash != null) {
            jwtClaimsSet.setClaim(AT_HASH, atHash);
        }
        if (nonceValue != null) {
            jwtClaimsSet.setClaim(NONCE, nonceValue);
        }
        if (acrValue != null) {
            jwtClaimsSet.setClaim(OAuthConstants.OIDCClaims.ACR, "urn:mace:incommon:iap:silver");
        }

        tokenReqMsgCtxt.addProperty(OAuthConstants.ACCESS_TOKEN, accessToken);
        tokenReqMsgCtxt.addProperty(MultitenantConstants.TENANT_DOMAIN, getSpTenantDomain(tokenReqMsgCtxt));

        handleOIDCCustomClaims(tokenReqMsgCtxt, jwtClaimsSet);
        jwtClaimsSet.setSubject(subjectClaim);

        if (isInvalidToken(jwtClaimsSet)) {
            throw new IDTokenValidationFailureException("Error while validating ID Token token for required claims");
        }

        if (isUnsignedIDToken()) {
            return new PlainJWT(jwtClaimsSet).serialize();
        }

        String signingTenantDomain = getSigningTenantDomain(tokenReqMsgCtxt);
        return OAuth2Util.signJWT(jwtClaimsSet, signatureAlgorithm, signingTenantDomain).serialize();
    }

    @Override
    public String buildIDToken(OAuthAuthzReqMessageContext authzReqMessageContext,
                               OAuth2AuthorizeRespDTO tokenRespDTO) throws IdentityOAuth2Exception {

        String accessToken = tokenRespDTO.getAccessToken();
        String clientId = authzReqMessageContext.getAuthorizationReqDTO().getConsumerKey();
        String spTenantDomain = getSpTenantDomain(authzReqMessageContext);
        String issuer = getIdTokenIssuer(spTenantDomain);

        // Get subject from Authenticated Subject Identifier
        AuthenticatedUser authorizedUser = authzReqMessageContext.getAuthorizationReqDTO().getUser();
        String subject = getSubjectClaim(authzReqMessageContext, tokenRespDTO, clientId, spTenantDomain, authorizedUser);

        String nonceValue = authzReqMessageContext.getAuthorizationReqDTO().getNonce();
        LinkedHashSet acrValue = authzReqMessageContext.getAuthorizationReqDTO().getACRValues();

        long idTokenLifeTimeInMillis = getIDTokenExpiryInMillis();
        long currentTimeInMillis = Calendar.getInstance().getTimeInMillis();

        if (log.isDebugEnabled()) {
            log.debug(buildDebugMessage(issuer, subject, nonceValue, idTokenLifeTimeInMillis, currentTimeInMillis));
        }

        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet();
        jwtClaimsSet.setIssuer(issuer);

        // Set the audience
        List<String> audience = getOIDCAudience(clientId);
        jwtClaimsSet.setAudience(audience);

        jwtClaimsSet.setClaim(AZP, clientId);
        jwtClaimsSet.setExpirationTime(getIdTokenExpiryInMillis(idTokenLifeTimeInMillis, currentTimeInMillis));
        jwtClaimsSet.setIssueTime(new Date(currentTimeInMillis));

        long authTime = getAuthTime(authzReqMessageContext, accessToken);
        if (authTime != 0) {
            jwtClaimsSet.setClaim(AUTH_TIME, authTime / 1000);
        }

        String responseType = authzReqMessageContext.getAuthorizationReqDTO().getResponseType();
        if (isIDTokenSigned() && isAccessTokenHashApplicable(responseType) && isNotBlank(accessToken)) {
            String atHash = getAtHash(accessToken);
            jwtClaimsSet.setClaim(AT_HASH, atHash);
        }

        if (nonceValue != null) {
            jwtClaimsSet.setClaim(OAuthConstants.OIDCClaims.NONCE, nonceValue);
        }
        if (acrValue != null) {
            jwtClaimsSet.setClaim(OAuthConstants.OIDCClaims.ACR, "urn:mace:incommon:iap:silver");
        }

        authzReqMessageContext.addProperty(OAuthConstants.ACCESS_TOKEN, accessToken);
        authzReqMessageContext.addProperty(MultitenantConstants.TENANT_DOMAIN, getSpTenantDomain(authzReqMessageContext));

        handleCustomOIDCClaims(authzReqMessageContext, jwtClaimsSet);
        jwtClaimsSet.setSubject(subject);

        if (isUnsignedIDToken()) {
            return new PlainJWT(jwtClaimsSet).serialize();
        }

        String signingTenantDomain = getSigningTenantDomain(authzReqMessageContext);
        return OAuth2Util.signJWT(jwtClaimsSet, signatureAlgorithm, signingTenantDomain).serialize();
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

    private boolean isEssentialClaim(AuthorizationGrantCacheEntry authorizationGrantCacheEntry,
                                     String oidcClaimUri) {
        return OAuth2Util.getEssentialClaims(authorizationGrantCacheEntry.getEssentialClaims(), OAuthConstants.ID_TOKEN)
                .contains(oidcClaimUri);
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

    private void handleOIDCCustomClaims(OAuthTokenReqMessageContext tokReqMsgCtx, JWTClaimsSet jwtClaimsSet) {
        CustomClaimsCallbackHandler claimsCallBackHandler =
                OAuthServerConfiguration.getInstance().getOpenIDConnectCustomClaimsCallbackHandler();
        claimsCallBackHandler.handleCustomClaims(jwtClaimsSet, tokReqMsgCtx);
    }

    private String getSubjectClaimForLocalUser(ServiceProvider serviceProvider,
                                               AuthenticatedUser authorizedUser) throws IdentityOAuth2Exception {
        String subject;
        String username = authorizedUser.getUserName();
        String userStoreDomain = authorizedUser.getUserStoreDomain();
        String userTenantDomain = authorizedUser.getTenantDomain();

        String subjectClaimUri = getSubjectClaimUriInLocalDialect(serviceProvider);
        if (subjectClaimUri != null) {
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
                String error = "Error occurred while getting user claim for user: " + authorizedUser + ", claim: " + subjectClaimUri;
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

    private List<String> getOIDCAudience(String clientId) {
        List<String> oidcAudiences = getDefinedCustomOIDCAudiences();
        // Need to add client_id as an audience value according to the spec.
        oidcAudiences.add(clientId);
        return oidcAudiences;
    }

    private String getAtHash(String accessToken) throws IdentityOAuth2Exception {
        String digAlg = OAuth2Util.mapDigestAlgorithm(signatureAlgorithm);
        MessageDigest md;
        try {
            md = MessageDigest.getInstance(digAlg);
        } catch (NoSuchAlgorithmException e) {
            throw new IdentityOAuth2Exception("Error creating the at_hash value. Invalid Digest Algorithm: " + digAlg);
        }

        md.update(accessToken.getBytes(Charsets.UTF_8));
        byte[] digest = md.digest();
        int leftHalfBytes = 16;
        if (SHA384.equals(digAlg)) {
            leftHalfBytes = 24;
        } else if (SHA512.equals(digAlg)) {
            leftHalfBytes = 32;
        }
        byte[] leftmost = new byte[leftHalfBytes];
        System.arraycopy(digest, 0, leftmost, 0, leftHalfBytes);
        return new String(Base64.encodeBase64URLSafe(leftmost), Charsets.UTF_8);
    }

    private ServiceProvider getServiceProvider(String spTenantDomain,
                                               String clientId) throws IdentityOAuth2Exception {
        ApplicationManagementService applicationMgtService = OAuth2ServiceComponentHolder.getApplicationMgtService();
        try {
            String spName =
                    applicationMgtService.getServiceProviderNameByClientId(clientId, INBOUND_AUTH2_TYPE, spTenantDomain);
            return applicationMgtService.getApplicationExcludingFileBasedSPs(spName, spTenantDomain);
        } catch (IdentityApplicationManagementException e) {
            throw new IdentityOAuth2Exception("Error while getting service provider information for client_id: "
                    + clientId + " tenantDomain: " + spTenantDomain, e);
        }
    }

    private String getIdTokenIssuer(String tenantDomain) throws IdentityOAuth2Exception {
        IdentityProvider identityProvider = getResidentIdp(tenantDomain);
        FederatedAuthenticatorConfig[] fedAuthnConfigs = identityProvider.getFederatedAuthenticatorConfigs();
        // Get OIDC authenticator
        FederatedAuthenticatorConfig oidcAuthenticatorConfig =
                IdentityApplicationManagementUtil.getFederatedAuthenticator(fedAuthnConfigs,
                        IdentityApplicationConstants.Authenticator.OIDC.NAME);
        return IdentityApplicationManagementUtil.getProperty(oidcAuthenticatorConfig.getProperties(),
                OPENID_IDP_ENTITY_ID).getValue();
    }

    private long getAuthTime(OAuthAuthzReqMessageContext authzReqMessageContext, String accessToken) {
        long authTime = 0;
        if (StringUtils.isNotEmpty(accessToken)) {
            AuthorizationGrantCacheKey authzGrantCacheKey = new AuthorizationGrantCacheKey(accessToken);
            AuthorizationGrantCacheEntry authzGrantCacheEntry =
                    AuthorizationGrantCache.getInstance().getValueFromCacheByToken(authzGrantCacheKey);
            if (authzGrantCacheEntry != null) {
                if (isNotBlank(authzGrantCacheEntry.getEssentialClaims())) {
                    if (isEssentialClaim(authzGrantCacheEntry, AUTH_TIME)) {
                        authTime = authzReqMessageContext.getAuthorizationReqDTO().getAuthTime();
                    }
                }
            }
        }
        return authTime;
    }

    private boolean isAccessTokenHashApplicable(String responseType) {
        // At_hash is generated on an access token. Therefore check whether the response type returns an access_token.
        // id_token and none response types don't return and access token
        return !OAuthConstants.ID_TOKEN.equalsIgnoreCase(responseType) &&
                !OAuthConstants.NONE.equalsIgnoreCase(responseType);
    }

    private Date getIdTokenExpiryInMillis(long currentTimeInMillis, long lifetimeInMillis) {
        return new Date(currentTimeInMillis + lifetimeInMillis);
    }

    private void handleCustomOIDCClaims(OAuthAuthzReqMessageContext request, JWTClaimsSet jwtClaimsSet) {
        CustomClaimsCallbackHandler claimsCallBackHandler =
                OAuthServerConfiguration.getInstance().getOpenIDConnectCustomClaimsCallbackHandler();
        claimsCallBackHandler.handleCustomClaims(jwtClaimsSet, request);
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
     * @param request
     * @return AuthorizationGrantCacheEntry contains user attributes and nonce value
     */
    private AuthorizationGrantCacheEntry getAuthorizationGrantCacheEntry(OAuthTokenReqMessageContext request) {
        String authorizationCode = getAuthorizationCode(request);
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

    private List<String> getDefinedCustomOIDCAudiences() {
        List<String> audiences = new ArrayList<>();
        IdentityConfigParser configParser = IdentityConfigParser.getInstance();
        OMElement oauthElem = configParser.getConfigElement(CONFIG_ELEM_OAUTH);
        if (oauthElem == null) {
            warnOnFaultyConfiguration("<OAuth> configuration element is not available in identity.xml.");
            return audiences;
        }

        OMElement oidcConfig = oauthElem.getFirstChildWithName(getQNameWithIdentityNS(OPENID_CONNECT));
        if (oidcConfig == null) {
            warnOnFaultyConfiguration("<OpenIDConnect> element is not available in identity.xml.");
            return audiences;
        }

        OMElement audienceConfig = oidcConfig.getFirstChildWithName(getQNameWithIdentityNS(OPENID_CONNECT_AUDIENCES));
        if (audienceConfig == null) {
            return audiences;
        }

        Iterator iterator = audienceConfig.getChildrenWithName(getQNameWithIdentityNS(OPENID_CONNECT_AUDIENCE));
        while (iterator.hasNext()) {
            OMElement supportedAudience = (OMElement) iterator.next();
            String supportedAudienceName;
            if (supportedAudience != null) {
                supportedAudienceName = IdentityUtil.fillURLPlaceholders(supportedAudience.getText());
                if (isNotBlank(supportedAudienceName)) {
                    audiences.add(supportedAudienceName);
                }
            }
        }
        return audiences;
    }

    private void warnOnFaultyConfiguration(String logMsg) {
        log.warn("Error in OAuth Configuration: " + logMsg);
    }

    private QName getQNameWithIdentityNS(String localPart) {
        return new QName(IdentityCoreConstants.IDENTITY_DEFAULT_NAMESPACE, localPart);
    }

    private IdentityProvider getResidentIdp(String tenantDomain) throws IdentityOAuth2Exception {
        try {
            return IdentityProviderManager.getInstance().getResidentIdP(tenantDomain);
        } catch (IdentityProviderManagementException e) {
            final String ERROR_GET_RESIDENT_IDP = "Error while getting Resident Identity Provider of '%s' tenant.";
            String errorMsg = String.format(ERROR_GET_RESIDENT_IDP, tenantDomain);
            throw new IdentityOAuth2Exception(errorMsg, e);
        }
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

    private long getIDTokenExpiryInMillis() {
        return OAuthServerConfiguration.getInstance().getOpenIDConnectIDTokenExpiryTimeInSeconds() * 1000L;
    }
}

