/*
 * Copyright (c) 2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import org.apache.axiom.om.OMElement;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.io.Charsets;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.Claim;
import org.wso2.carbon.identity.application.common.model.ClaimConfig;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.cache.CacheEntry;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDAO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dao.TokenMgtDAO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;

import java.security.Key;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import javax.xml.namespace.QName;

/**
 * This is the IDToken generator for the OpenID Connect Implementation. This
 * IDToken Generator utilizes the Nimbus SDK to build the IDToken.
 */
public class DefaultIDTokenBuilder implements org.wso2.carbon.identity.openidconnect.IDTokenBuilder {

    private static final String NONE = "NONE";
    private static final String SHA256_WITH_RSA = "SHA256withRSA";
    private static final String SHA384_WITH_RSA = "SHA384withRSA";
    private static final String SHA512_WITH_RSA = "SHA512withRSA";
    private static final String SHA256_WITH_HMAC = "SHA256withHMAC";
    private static final String SHA384_WITH_HMAC = "SHA384withHMAC";
    private static final String SHA512_WITH_HMAC = "SHA512withHMAC";
    private static final String SHA256_WITH_EC = "SHA256withEC";
    private static final String SHA384_WITH_EC = "SHA384withEC";
    private static final String SHA512_WITH_EC = "SHA512withEC";
    private static final String SHA256 = "SHA-256";
    private static final String SHA384 = "SHA-384";
    private static final String SHA512 = "SHA-512";
    private static final String AUTHORIZATION_CODE = "AuthorizationCode";
    private static final String INBOUND_AUTH2_TYPE = "oauth2";
    private static final String CONFIG_ELEM_OAUTH = "OAuth";
    private static final String OPENID_CONNECT = "OpenIDConnect";
    private static final String OPENID_CONNECT_AUDIENCES = "Audiences";
    private static final String OPENID_CONNECT_AUDIENCE = "Audience";
    private static final String OPENID_IDP_ENTITY_ID = "IdPEntityId";
    private static final String kid = "d0ec514a32b6f88c0abd12a2840699bdd3deba9d";

    private static final Log log = LogFactory.getLog(DefaultIDTokenBuilder.class);
    private static Map<Integer, Key> privateKeys = new ConcurrentHashMap<>();
    private static Map<Integer, Certificate> publicCerts = new ConcurrentHashMap<>();
    private OAuthServerConfiguration config = null;
    private Algorithm signatureAlgorithm = null;

    private static final String ERROR_GET_RESIDENT_IDP =
            "Error while getting Resident Identity Provider of '%s' tenant.";

    public DefaultIDTokenBuilder() throws IdentityOAuth2Exception {

        config = OAuthServerConfiguration.getInstance();
        //map signature algorithm from identity.xml to nimbus format, this is a one time configuration
        signatureAlgorithm = mapSignatureAlgorithm(config.getIdTokenSignatureAlgorithm());
    }

    @Override
    public String buildIDToken(OAuthTokenReqMessageContext request, OAuth2AccessTokenRespDTO tokenRespDTO)
            throws IdentityOAuth2Exception {

        String tenantDomain = request.getOauth2AccessTokenReqDTO().getTenantDomain();
        IdentityProvider identityProvider = getResidentIdp(tenantDomain);

        FederatedAuthenticatorConfig[] fedAuthnConfigs = identityProvider.getFederatedAuthenticatorConfigs();

        // Get OIDC authenticator
        FederatedAuthenticatorConfig samlAuthenticatorConfig =
                IdentityApplicationManagementUtil.getFederatedAuthenticator(fedAuthnConfigs,
                        IdentityApplicationConstants.Authenticator.OIDC.NAME);
        String issuer =
                IdentityApplicationManagementUtil.getProperty(samlAuthenticatorConfig.getProperties(),
                        OPENID_IDP_ENTITY_ID).getValue();

        long lifetimeInMillis = Integer.parseInt(config.getOpenIDConnectIDTokenExpiration()) * 1000;
        long curTimeInMillis = Calendar.getInstance().getTimeInMillis();
        // setting subject
        String subject = request.getAuthorizedUser().getAuthenticatedSubjectIdentifier();

        if (!GrantType.AUTHORIZATION_CODE.toString().equals(request.getOauth2AccessTokenReqDTO().getGrantType()) &&
                !org.wso2.carbon.identity.oauth.common.GrantType.SAML20_BEARER.toString().equals(
                        request.getOauth2AccessTokenReqDTO().getGrantType())) {

            ApplicationManagementService applicationMgtService = OAuth2ServiceComponentHolder
                    .getApplicationMgtService();
            ServiceProvider serviceProvider = null;

            try {
                String spName = applicationMgtService.getServiceProviderNameByClientId(
                        request.getOauth2AccessTokenReqDTO().getClientId(), INBOUND_AUTH2_TYPE, tenantDomain);
                serviceProvider = applicationMgtService.getApplicationExcludingFileBasedSPs(spName, tenantDomain);
            } catch (IdentityApplicationManagementException e) {
                throw new IdentityOAuth2Exception("Error while getting service provider information.", e);
            }

            if (serviceProvider != null) {
                String subjectClaim = serviceProvider.getLocalAndOutBoundAuthenticationConfig().getSubjectClaimUri();
                ClaimConfig claimConfig = serviceProvider.getClaimConfig();

                if (claimConfig != null) {
                    boolean isLocalClaimDialect = claimConfig.isLocalClaimDialect();
                    ClaimMapping[] claimMappings = claimConfig.getClaimMappings();

                    if (!isLocalClaimDialect && claimMappings.length > 0) {
                        for (ClaimMapping claimMapping : claimMappings) {
                            if (StringUtils.isNotBlank(subjectClaim) && StringUtils
                                    .equals(claimMapping.getRemoteClaim().getClaimUri(), subjectClaim)) {
                                subjectClaim = claimMapping.getLocalClaim().getClaimUri();
                            }
                        }
                    }
                }

                if (subjectClaim != null) {
                    String username = request.getAuthorizedUser().getUserName();
                    String userStore = request.getAuthorizedUser().getUserStoreDomain();
                    tenantDomain = request.getAuthorizedUser().getTenantDomain();
                    String fqdnUsername = request.getAuthorizedUser().toString();
                    try {
                        UserStoreManager usm = IdentityTenantUtil.getRealm(tenantDomain,
                                                                           fqdnUsername).getUserStoreManager();
                        subject = usm.getSecondaryUserStoreManager(userStore).getUserClaimValue(username, subjectClaim, null);
                        if (StringUtils.isBlank(subject)) {
                            subject = request.getAuthorizedUser().getAuthenticatedSubjectIdentifier();
                        }
                        if (serviceProvider.getLocalAndOutBoundAuthenticationConfig().isUseTenantDomainInLocalSubjectIdentifier()) {
                            subject = subject + UserCoreConstants.TENANT_DOMAIN_COMBINER + tenantDomain;
                        }
                    } catch (IdentityException e) {
                        String error = "Error occurred while getting user claim for user " + request
                                .getAuthorizedUser().toString() + ", claim " + subjectClaim;
                        throw new IdentityOAuth2Exception(error, e);
                    } catch (UserStoreException e) {
                        if (e.getMessage().contains("UserNotFound")) {
                            if (log.isDebugEnabled()) {
                                log.debug("User " + username + " not found in user store " + userStore + " in tenant " +
                                          tenantDomain);
                            }
                            subject = request.getAuthorizedUser().toString();
                        } else {
                            String error = "Error occurred while getting user claim for user " + request
                                    .getAuthorizedUser().toString() + ", claim " + subjectClaim;
                            throw new IdentityOAuth2Exception(error, e);
                        }

                    }
                }
            }
        }

        String nonceValue = null;
        long authTime = 0;

        LinkedHashSet acrValue = new LinkedHashSet();
        // AuthorizationCode only available for authorization code grant type
        if (request.getProperty(AUTHORIZATION_CODE) != null) {
            AuthorizationGrantCacheEntry authorizationGrantCacheEntry = getAuthorizationGrantCacheEntry(request);
            if (authorizationGrantCacheEntry != null) {
                nonceValue = authorizationGrantCacheEntry.getNonceValue();
                acrValue = authorizationGrantCacheEntry.getAcrValue();
                authTime = authorizationGrantCacheEntry.getAuthTime();
            }
        }
        // Get access token issued time
        long accessTokenIssuedTime = getAccessTokenIssuedTime(tokenRespDTO.getAccessToken(), request) / 1000;

        String atHash = null;
        if (!JWSAlgorithm.NONE.getName().equals(signatureAlgorithm.getName())) {
            String digAlg = mapDigestAlgorithm(signatureAlgorithm);
            MessageDigest md;
            try {
                md = MessageDigest.getInstance(digAlg);
            } catch (NoSuchAlgorithmException e) {
                throw new IdentityOAuth2Exception("Invalid Algorithm : " + digAlg);
            }
            md.update(tokenRespDTO.getAccessToken().getBytes(Charsets.UTF_8));
            byte[] digest = md.digest();
            int leftHalfBytes = 16;
            if (SHA384.equals(digAlg)) {
                leftHalfBytes = 24;
            } else if (SHA512.equals(digAlg)) {
                leftHalfBytes = 32;
            }
            byte[] leftmost = new byte[leftHalfBytes];
            for (int i = 0; i < leftHalfBytes; i++) {
                leftmost[i] = digest[i];
            }
            atHash = new String(Base64.encodeBase64URLSafe(leftmost), Charsets.UTF_8);
        }


        if (log.isDebugEnabled()) {
            StringBuilder stringBuilder = (new StringBuilder())
                    .append("Using issuer ").append(issuer).append("\n")
                    .append("Subject ").append(subject).append("\n")
                    .append("ID Token life time ").append(lifetimeInMillis / 1000).append("\n")
                    .append("Current time ").append(curTimeInMillis / 1000).append("\n")
                    .append("Nonce Value ").append(nonceValue).append("\n")
                    .append("Signature Algorithm ").append(signatureAlgorithm).append("\n");
            log.debug(stringBuilder.toString());
        }

        ArrayList<String> audience = new ArrayList<String>();
        audience.add(request.getOauth2AccessTokenReqDTO().getClientId());
        if (CollectionUtils.isNotEmpty(getOIDCEndpointUrl(request.getOauth2AccessTokenReqDTO().getTenantDomain(), request.getOauth2AccessTokenReqDTO().getClientId()))) {
            audience.addAll(getOIDCEndpointUrl(request.getOauth2AccessTokenReqDTO().getTenantDomain(), request.getOauth2AccessTokenReqDTO().getClientId()));
        }

        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet();
        jwtClaimsSet.setIssuer(issuer);
        jwtClaimsSet.setAudience(audience);
        jwtClaimsSet.setClaim("azp", request.getOauth2AccessTokenReqDTO().getClientId());
        jwtClaimsSet.setExpirationTime(new Date(curTimeInMillis + lifetimeInMillis));
        jwtClaimsSet.setIssueTime(new Date(curTimeInMillis));
        if (authTime != 0) {
            jwtClaimsSet.setClaim("auth_time", authTime / 1000);
        }
        if(atHash != null){
            jwtClaimsSet.setClaim("at_hash", atHash);
        }
        if (nonceValue != null) {
            jwtClaimsSet.setClaim("nonce", nonceValue);
        }
        if (acrValue != null) {
            jwtClaimsSet.setClaim("acr", "urn:mace:incommon:iap:silver");
        }

        request.addProperty(OAuthConstants.ACCESS_TOKEN, tokenRespDTO.getAccessToken());
        request.addProperty(MultitenantConstants.TENANT_DOMAIN, request.getOauth2AccessTokenReqDTO().getTenantDomain());
        CustomClaimsCallbackHandler claimsCallBackHandler =
                OAuthServerConfiguration.getInstance().getOpenIDConnectCustomClaimsCallbackHandler();
        claimsCallBackHandler.handleCustomClaims(jwtClaimsSet, request);
        jwtClaimsSet.setSubject(subject);
        if (JWSAlgorithm.NONE.getName().equals(signatureAlgorithm.getName())) {
            return new PlainJWT(jwtClaimsSet).serialize();
        }
        return signJWT(jwtClaimsSet, request);
    }

    @Override
    public String buildIDToken(OAuthAuthzReqMessageContext request, OAuth2AuthorizeRespDTO tokenRespDTO)
            throws IdentityOAuth2Exception {

        String tenantDomain = request.getAuthorizationReqDTO().getTenantDomain();
        IdentityProvider identityProvider = getResidentIdp(tenantDomain);

        FederatedAuthenticatorConfig[] fedAuthnConfigs = identityProvider.getFederatedAuthenticatorConfigs();

        // Get OIDC authenticator
        FederatedAuthenticatorConfig samlAuthenticatorConfig =
                IdentityApplicationManagementUtil.getFederatedAuthenticator(fedAuthnConfigs,
                        IdentityApplicationConstants.Authenticator.OIDC.NAME);
        String issuer =
                IdentityApplicationManagementUtil.getProperty(samlAuthenticatorConfig.getProperties(),
                        OPENID_IDP_ENTITY_ID).getValue();

        long lifetimeInMillis = Integer.parseInt(config.getOpenIDConnectIDTokenExpiration()) * 1000;
        long curTimeInMillis = Calendar.getInstance().getTimeInMillis();
        // setting subject
        String subject = request.getAuthorizationReqDTO().getUser().getAuthenticatedSubjectIdentifier();

        String nonceValue = request.getAuthorizationReqDTO().getNonce();
        LinkedHashSet acrValue = request.getAuthorizationReqDTO().getACRValues();

        // Get access token issued time
        long accessTokenIssuedTime = getAccessTokenIssuedTime(tokenRespDTO.getAccessToken(), request) / 1000;

        String atHash = null;
        String responseType = request.getAuthorizationReqDTO().getResponseType();
        //at_hash is generated on access token. Hence the check on response type to be id_token token or code
        if (!JWSAlgorithm.NONE.getName().equals(signatureAlgorithm.getName()) &&
                !OAuthConstants.ID_TOKEN.equalsIgnoreCase(responseType) &&
                !OAuthConstants.NONE.equalsIgnoreCase(responseType)) {
            String digAlg = mapDigestAlgorithm(signatureAlgorithm);
            MessageDigest md;
            try {
                md = MessageDigest.getInstance(digAlg);
            } catch (NoSuchAlgorithmException e) {
                throw new IdentityOAuth2Exception("Invalid Algorithm : " + digAlg);
            }
            md.update(tokenRespDTO.getAccessToken().getBytes(Charsets.UTF_8));
            byte[] digest = md.digest();
            int leftHalfBytes = 16;
            if (SHA384.equals(digAlg)) {
                leftHalfBytes = 24;
            } else if (SHA512.equals(digAlg)) {
                leftHalfBytes = 32;
            }
            byte[] leftmost = new byte[leftHalfBytes];
            for (int i = 0; i < leftHalfBytes; i++) {
                leftmost[i] = digest[i];
            }
            atHash = new String(Base64.encodeBase64URLSafe(leftmost), Charsets.UTF_8);
        }


        if (log.isDebugEnabled()) {
            StringBuilder stringBuilder = (new StringBuilder())
                    .append("Using issuer ").append(issuer).append("\n")
                    .append("Subject ").append(subject).append("\n")
                    .append("ID Token life time ").append(lifetimeInMillis / 1000).append("\n")
                    .append("Current time ").append(curTimeInMillis / 1000).append("\n")
                    .append("Nonce Value ").append(nonceValue).append("\n")
                    .append("Signature Algorithm ").append(signatureAlgorithm).append("\n");
            if (log.isDebugEnabled()) {
                log.debug(stringBuilder.toString());
            }
        }

        ArrayList<String> audience = new ArrayList<String>();
        audience.add(request.getAuthorizationReqDTO().getConsumerKey());
        if (CollectionUtils.isNotEmpty(getOIDCEndpointUrl(request.getAuthorizationReqDTO().getTenantDomain(), request.getAuthorizationReqDTO().getConsumerKey()))) {
            audience.addAll(getOIDCEndpointUrl(request.getAuthorizationReqDTO().getTenantDomain(), request.getAuthorizationReqDTO().getConsumerKey()));
        }

        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet();
        jwtClaimsSet.setIssuer(issuer);
        jwtClaimsSet.setAudience(audience);
        jwtClaimsSet.setClaim("azp", request.getAuthorizationReqDTO().getConsumerKey());
        jwtClaimsSet.setExpirationTime(new Date(curTimeInMillis + lifetimeInMillis));
        jwtClaimsSet.setIssueTime(new Date(curTimeInMillis));
        if (request.getAuthorizationReqDTO().getAuthTime() != 0) {
            jwtClaimsSet.setClaim("auth_time", request.getAuthorizationReqDTO().getAuthTime() / 1000);
        }
        if(atHash != null){
            jwtClaimsSet.setClaim("at_hash", atHash);
        }
        if (nonceValue != null) {
            jwtClaimsSet.setClaim("nonce", nonceValue);
        }
        if (acrValue != null) {
            jwtClaimsSet.setClaim("acr", "urn:mace:incommon:iap:silver");
        }

        request.addProperty(OAuthConstants.ACCESS_TOKEN, tokenRespDTO.getAccessToken());
        request.addProperty(MultitenantConstants.TENANT_DOMAIN, request.getAuthorizationReqDTO().getTenantDomain());
        CustomClaimsCallbackHandler claimsCallBackHandler =
                OAuthServerConfiguration.getInstance().getOpenIDConnectCustomClaimsCallbackHandler();
        claimsCallBackHandler.handleCustomClaims(jwtClaimsSet, request);
        jwtClaimsSet.setSubject(subject);
        if (JWSAlgorithm.NONE.getName().equals(signatureAlgorithm.getName())) {
            return new PlainJWT(jwtClaimsSet).serialize();
        }
        return signJWT(jwtClaimsSet, request);
    }

    /**
     * sign JWT token from RSA algorithm
     *
     * @param jwtClaimsSet contains JWT body
     * @param request
     * @return signed JWT token
     * @throws IdentityOAuth2Exception
     */
    protected String signJWTWithRSA(JWTClaimsSet jwtClaimsSet, OAuthTokenReqMessageContext request)
            throws IdentityOAuth2Exception {
        try {

            boolean isJWTSignedWithSPKey = OAuthServerConfiguration.getInstance().isJWTSignedWithSPKey();
            String tenantDomain = null;
            if(isJWTSignedWithSPKey) {
                tenantDomain = (String) request.getProperty(MultitenantConstants.TENANT_DOMAIN);
            } else {
                tenantDomain = request.getAuthorizedUser().getTenantDomain();
            }

            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);

            Key privateKey = getPrivateKey(tenantDomain, tenantId);
            JWSSigner signer = new RSASSASigner((RSAPrivateKey) privateKey);
            JWSHeader header = new JWSHeader((JWSAlgorithm) signatureAlgorithm);
            header.setKeyID(kid);
            header.setX509CertThumbprint(new Base64URL(getThumbPrint(tenantDomain, tenantId)));
            SignedJWT signedJWT = new SignedJWT(header, jwtClaimsSet);
            signedJWT.sign(signer);
            return signedJWT.serialize();
        } catch (JOSEException e) {
            throw new IdentityOAuth2Exception("Error occurred while signing JWT", e);
        }
    }

    protected String signJWTWithRSA(JWTClaimsSet jwtClaimsSet, OAuthAuthzReqMessageContext request)
            throws IdentityOAuth2Exception {
        try {

            boolean isJWTSignedWithSPKey = OAuthServerConfiguration.getInstance().isJWTSignedWithSPKey();
            String tenantDomain = null;
            if(isJWTSignedWithSPKey) {
                tenantDomain = (String) request.getProperty(MultitenantConstants.TENANT_DOMAIN);
            } else {
                tenantDomain = request.getAuthorizationReqDTO().getUser().getTenantDomain();
            }

            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);

            Key privateKey = getPrivateKey(tenantDomain, tenantId);
            JWSSigner signer = new RSASSASigner((RSAPrivateKey) privateKey);
            JWSHeader header = new JWSHeader((JWSAlgorithm) signatureAlgorithm);
            header.setX509CertThumbprint(new Base64URL(getThumbPrint(tenantDomain, tenantId)));
            header.setKeyID(kid);
            SignedJWT signedJWT = new SignedJWT(header, jwtClaimsSet);
            signedJWT.sign(signer);
            return signedJWT.serialize();
        } catch (JOSEException e) {
            throw new IdentityOAuth2Exception("Error occurred while signing JWT", e);
        }
    }

    private Key getPrivateKey(String tenantDomain, int tenantId) throws IdentityOAuth2Exception {
        Key privateKey;
        if (!(privateKeys.containsKey(tenantId))) {

            try {
                IdentityTenantUtil.initializeRegistry(tenantId, tenantDomain);
            } catch (IdentityException e) {
                throw new IdentityOAuth2Exception("Error occurred while loading registry for tenant " + tenantDomain,
                        e);
            }

            // get tenant's key store manager
            KeyStoreManager tenantKSM = KeyStoreManager.getInstance(tenantId);

            if (!tenantDomain.equals(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME)) {
                // derive key store name
                String ksName = tenantDomain.trim().replace(".", "-");
                String jksName = ksName + ".jks";
                // obtain private key
                privateKey = tenantKSM.getPrivateKey(jksName, tenantDomain);

            } else {
                try {
                    privateKey = tenantKSM.getDefaultPrivateKey();
                } catch (Exception e) {
                    throw new IdentityOAuth2Exception("Error while obtaining private key for super tenant", e);
                }
            }
            //privateKey will not be null always
            privateKeys.put(tenantId, privateKey);
        } else {
            //privateKey will not be null because containsKey() true says given key is exist and ConcurrentHashMap
            // does not allow to store null values
            privateKey = privateKeys.get(tenantId);
        }
        return privateKey;
    }

    /**
     * @param request
     * @return AuthorizationGrantCacheEntry contains user attributes and nonce value
     */
    private AuthorizationGrantCacheEntry getAuthorizationGrantCacheEntry(
            OAuthTokenReqMessageContext request) {

        String authorizationCode = (String) request.getProperty(AUTHORIZATION_CODE);
        AuthorizationGrantCacheKey authorizationGrantCacheKey = new AuthorizationGrantCacheKey(authorizationCode);
        AuthorizationGrantCacheEntry authorizationGrantCacheEntry =
                (AuthorizationGrantCacheEntry) AuthorizationGrantCache.getInstance().
                        getValueFromCacheByCode(authorizationGrantCacheKey);
        return authorizationGrantCacheEntry;
    }

    private long getAccessTokenIssuedTime(String accessToken, OAuthTokenReqMessageContext request)
            throws IdentityOAuth2Exception {

        AccessTokenDO accessTokenDO = null;
        TokenMgtDAO tokenMgtDAO = new TokenMgtDAO();

        OAuthCache oauthCache = OAuthCache.getInstance();
        String authorizedUser = request.getAuthorizedUser().toString();
        boolean isUsernameCaseSensitive = IdentityUtil.isUserStoreInUsernameCaseSensitive(authorizedUser);
        if (!isUsernameCaseSensitive) {
            authorizedUser = authorizedUser.toLowerCase();
        }

        OAuthCacheKey cacheKey = new OAuthCacheKey(
                request.getOauth2AccessTokenReqDTO().getClientId() + ":" + authorizedUser +
                        ":" + OAuth2Util.buildScopeString(request.getScope()));
        CacheEntry result = oauthCache.getValueFromCache(cacheKey);

        // cache hit, do the type check.
        if (result instanceof AccessTokenDO) {
            accessTokenDO = (AccessTokenDO) result;
        }

        // Cache miss, load the access token info from the database.
        if (accessTokenDO == null) {
            accessTokenDO = tokenMgtDAO.retrieveAccessToken(accessToken, false);
        }

        // if the access token or client id is not valid
        if (accessTokenDO == null) {
            throw new IdentityOAuth2Exception("Access token based information is not available in cache or database");
        }

        return accessTokenDO.getIssuedTime().getTime();
    }

    private long getAccessTokenIssuedTime(String accessToken, OAuthAuthzReqMessageContext request)
            throws IdentityOAuth2Exception {

        AccessTokenDO accessTokenDO = null;
        TokenMgtDAO tokenMgtDAO = new TokenMgtDAO();

        OAuthCache oauthCache = OAuthCache.getInstance();
        String authorizedUser = request.getAuthorizationReqDTO().getUser().toString();
        boolean isUsernameCaseSensitive = IdentityUtil.isUserStoreInUsernameCaseSensitive(authorizedUser);
        if (!isUsernameCaseSensitive){
            authorizedUser = authorizedUser.toLowerCase();
        }

        OAuthCacheKey cacheKey = new OAuthCacheKey(
                request.getAuthorizationReqDTO().getConsumerKey() + ":" + authorizedUser +
                        ":" + OAuth2Util.buildScopeString(request.getApprovedScope()));
        CacheEntry result = oauthCache.getValueFromCache(cacheKey);

        // cache hit, do the type check.
        if (result instanceof AccessTokenDO) {
            accessTokenDO = (AccessTokenDO) result;
        }

        // Cache miss, load the access token info from the database.
        if (accessTokenDO == null) {
            accessTokenDO = tokenMgtDAO.retrieveAccessToken(accessToken, false);
        }

        // if the access token or client id is not valid
        if (accessTokenDO == null) {
            throw new IdentityOAuth2Exception("Access token based information is not available in cache or database");
        }

        return accessTokenDO.getIssuedTime().getTime();
    }

    /**
     * Generic Signing function
     *
     * @param jwtClaimsSet contains JWT body
     * @param request
     * @return
     * @throws IdentityOAuth2Exception
     */
    protected String signJWT(JWTClaimsSet jwtClaimsSet, OAuthTokenReqMessageContext request)
            throws IdentityOAuth2Exception {

        if (JWSAlgorithm.RS256.equals(signatureAlgorithm) || JWSAlgorithm.RS384.equals(signatureAlgorithm) ||
                JWSAlgorithm.RS512.equals(signatureAlgorithm)) {
            return signJWTWithRSA(jwtClaimsSet, request);
        } else if (JWSAlgorithm.HS256.equals(signatureAlgorithm) || JWSAlgorithm.HS384.equals(signatureAlgorithm) ||
                JWSAlgorithm.HS512.equals(signatureAlgorithm)) {
            // return signWithHMAC(jwtClaimsSet,jwsAlgorithm,request); implementation need to be done
            return null;
        } else {
            // return signWithEC(jwtClaimsSet,jwsAlgorithm,request); implementation need to be done
            return null;
        }
    }

    protected String signJWT(JWTClaimsSet jwtClaimsSet, OAuthAuthzReqMessageContext request)
            throws IdentityOAuth2Exception {

        if (JWSAlgorithm.RS256.equals(signatureAlgorithm) || JWSAlgorithm.RS384.equals(signatureAlgorithm) ||
                JWSAlgorithm.RS512.equals(signatureAlgorithm)) {
            return signJWTWithRSA(jwtClaimsSet, request);
        } else if (JWSAlgorithm.HS256.equals(signatureAlgorithm) || JWSAlgorithm.HS384.equals(signatureAlgorithm) ||
                JWSAlgorithm.HS512.equals(signatureAlgorithm)) {
            // return signWithHMAC(jwtClaimsSet,jwsAlgorithm,request); implementation need to be done
            return null;
        } else {
            // return signWithEC(jwtClaimsSet,jwsAlgorithm,request); implementation need to be done
            return null;
        }
    }

    /**
     * This method map signature algorithm define in identity.xml to nimbus
     * signature algorithm
     * format, Strings are defined inline hence there are not being used any
     * where
     *
     * @param signatureAlgorithm
     * @return
     * @throws IdentityOAuth2Exception
     */
    protected JWSAlgorithm mapSignatureAlgorithm(String signatureAlgorithm) throws IdentityOAuth2Exception {

        if (NONE.equalsIgnoreCase(signatureAlgorithm)) {
            return new JWSAlgorithm(JWSAlgorithm.NONE.getName());
        } else if (SHA256_WITH_RSA.equals(signatureAlgorithm)) {
            return JWSAlgorithm.RS256;
        } else if (SHA384_WITH_RSA.equals(signatureAlgorithm)) {
            return JWSAlgorithm.RS384;
        } else if (SHA512_WITH_RSA.equals(signatureAlgorithm)) {
            return JWSAlgorithm.RS512;
        } else if (SHA256_WITH_HMAC.equals(signatureAlgorithm)) {
            return JWSAlgorithm.HS256;
        } else if (SHA384_WITH_HMAC.equals(signatureAlgorithm)) {
            return JWSAlgorithm.HS384;
        } else if (SHA512_WITH_HMAC.equals(signatureAlgorithm)) {
            return JWSAlgorithm.HS512;
        } else if (SHA256_WITH_EC.equals(signatureAlgorithm)) {
            return JWSAlgorithm.ES256;
        } else if (SHA384_WITH_EC.equals(signatureAlgorithm)) {
            return JWSAlgorithm.ES384;
        } else if (SHA512_WITH_EC.equals(signatureAlgorithm)) {
            return JWSAlgorithm.ES512;
        }
        throw new IdentityOAuth2Exception("Unsupported Signature Algorithm in identity.xml");
    }

    /**
     * This method maps signature algorithm define in identity.xml to digest algorithms to generate the at_hash
     *
     * @param signatureAlgorithm
     * @return
     * @throws IdentityOAuth2Exception
     */
    protected String mapDigestAlgorithm(Algorithm signatureAlgorithm) throws IdentityOAuth2Exception {

        if (JWSAlgorithm.RS256.equals(signatureAlgorithm) || JWSAlgorithm.HS256.equals(signatureAlgorithm) ||
            JWSAlgorithm.ES256.equals(signatureAlgorithm)) {
            return SHA256;
        } else if (JWSAlgorithm.RS384.equals(signatureAlgorithm) || JWSAlgorithm.HS384.equals(signatureAlgorithm) ||
                   JWSAlgorithm.ES384.equals(signatureAlgorithm)) {
            return SHA384;
        } else if (JWSAlgorithm.RS512.equals(signatureAlgorithm) || JWSAlgorithm.HS512.equals(signatureAlgorithm) ||
                   JWSAlgorithm.ES512.equals(signatureAlgorithm)) {
            return SHA512;
        }
        throw new RuntimeException("Cannot map Signature Algorithm in identity.xml to hashing algorithm");
    }

    /**
     * Helper method to add public certificate to JWT_HEADER to signature verification.
     *
     * @param tenantDomain
     * @param tenantId
     * @throws IdentityOAuth2Exception
     */
    private String getThumbPrint(String tenantDomain, int tenantId) throws IdentityOAuth2Exception {

        try {

            Certificate certificate = getCertificate(tenantDomain, tenantId);

            // TODO: maintain a hashmap with tenants' pubkey thumbprints after first initialization

            //generate the SHA-1 thumbprint of the certificate
            MessageDigest digestValue = MessageDigest.getInstance("SHA-1");
            byte[] der = certificate.getEncoded();
            digestValue.update(der);
            byte[] digestInBytes = digestValue.digest();

            String publicCertThumbprint = hexify(digestInBytes);
            String base64EncodedThumbPrint = new String(new Base64(0, null, true).encode(
                    publicCertThumbprint.getBytes(Charsets.UTF_8)), Charsets.UTF_8);
            return base64EncodedThumbPrint;

        } catch (Exception e) {
            String error = "Error in obtaining certificate for tenant " + tenantDomain;
            throw new IdentityOAuth2Exception(error, e);
        }
    }

    private Certificate getCertificate(String tenantDomain, int tenantId) throws Exception {

        if (tenantDomain == null) {
            tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        }

        if (tenantId == 0) {
            tenantId = OAuth2Util.getTenantId(tenantDomain);
        }

        Certificate publicCert = null;

        if (!(publicCerts.containsKey(tenantId))) {

            try {
                IdentityTenantUtil.initializeRegistry(tenantId, tenantDomain);
            } catch (IdentityException e) {
                throw new IdentityOAuth2Exception("Error occurred while loading registry for tenant " + tenantDomain, e);
            }

            // get tenant's key store manager
            KeyStoreManager tenantKSM = KeyStoreManager.getInstance(tenantId);

            KeyStore keyStore = null;
            if (!tenantDomain.equals(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME)) {
                // derive key store name
                String ksName = tenantDomain.trim().replace(".", "-");
                String jksName = ksName + ".jks";
                keyStore = tenantKSM.getKeyStore(jksName);
                publicCert = keyStore.getCertificate(tenantDomain);
            } else {
                publicCert = tenantKSM.getDefaultPrimaryCertificate();
            }
            if (publicCert != null) {
                publicCerts.put(tenantId, publicCert);
            }
        } else {
            publicCert = publicCerts.get(tenantId);
        }
        return publicCert;
    }

    /**
     * Helper method to hexify a byte array.
     * TODO:need to verify the logic
     *
     * @param bytes
     * @return  hexadecimal representation
     */
    private String hexify(byte bytes[]) {

        char[] hexDigits = {'0', '1', '2', '3', '4', '5', '6', '7',
                    +                            '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

        StringBuilder buf = new StringBuilder(bytes.length * 2);

        for (int i = 0; i < bytes.length; ++i) {
            buf.append(hexDigits[(bytes[i] & 0xf0) >> 4]);
            buf.append(hexDigits[bytes[i] & 0x0f]);
        }

        return buf.toString();
    }

    private List<String> getOIDCEndpointUrl(String tenantDomain, String consumerKey) {
        List<String> OIDCEntityId = getOIDCAudiences(tenantDomain, consumerKey);
        return OIDCEntityId;
    }

    private List<String> getOIDCAudiences(String tenantDomain, String consumerKey) {
        List<String> audiences = null;

        OAuthAppDAO oAuthAppDAO = new OAuthAppDAO();
        try {
            audiences = oAuthAppDAO.getOIDCAudiences(tenantDomain, consumerKey);
        } catch (IdentityOAuth2Exception e) {
            log.error("Error while retrieving OIDC audiences for tenant domain: "
                    + tenantDomain + " and client ID: " + consumerKey);
        }
        if(audiences == null || audiences.isEmpty()) {
            audiences = new ArrayList<String>();
            IdentityConfigParser configParser = IdentityConfigParser.getInstance();
            OMElement oauthElem = configParser.getConfigElement(CONFIG_ELEM_OAUTH);

            if (oauthElem == null) {
                warnOnFaultyConfiguration("OAuth element is not available.");
                return Collections.EMPTY_LIST;
            }
            OMElement configOpenIDConnect = oauthElem.getFirstChildWithName(getQNameWithIdentityNS(OPENID_CONNECT));

            if (configOpenIDConnect == null) {
                warnOnFaultyConfiguration("OpenID element is not available.");
                return Collections.EMPTY_LIST;
            }
            OMElement configAudience = configOpenIDConnect.
                    getFirstChildWithName(getQNameWithIdentityNS(OPENID_CONNECT_AUDIENCES));

            if (configAudience == null) {
                return Collections.EMPTY_LIST;
            }

            Iterator<OMElement> iterator =
                    configAudience.getChildrenWithName(getQNameWithIdentityNS(OPENID_CONNECT_AUDIENCE));
            while (iterator.hasNext()) {
                OMElement supportedAudience = iterator.next();
                String supportedAudienceName = null;

                if (supportedAudience != null) {
                    supportedAudienceName = IdentityUtil.fillURLPlaceholders(supportedAudience.getText());
                }
                if (StringUtils.isNotBlank(supportedAudienceName)) {
                    audiences.add(supportedAudienceName);
                }
            }
        }
        return audiences;
    }

    private void warnOnFaultyConfiguration(String logMsg) {
        log.warn("Error in OAuth Configuration. " + logMsg);
    }

    private QName getQNameWithIdentityNS(String localPart) {
        return new QName(IdentityCoreConstants.IDENTITY_DEFAULT_NAMESPACE, localPart);
    }

    private IdentityProvider getResidentIdp(String tenantDomain) throws IdentityOAuth2Exception {
        try {
            return IdentityProviderManager.getInstance().getResidentIdP(tenantDomain);
        } catch (IdentityProviderManagementException e) {
            String errorMsg = String.format(ERROR_GET_RESIDENT_IDP, tenantDomain);
            throw new IdentityOAuth2Exception(errorMsg, e);
        }
    }

}

