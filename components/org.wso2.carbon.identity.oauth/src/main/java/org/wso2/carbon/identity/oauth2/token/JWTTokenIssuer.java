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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.token;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
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
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AuthorizationGrantHandler;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.CustomClaimsCallbackHandler;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.security.Key;
import java.security.interfaces.RSAPrivateKey;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.apache.commons.lang.StringUtils.isNotBlank;
import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.getPrivateKey;

/**
 * Self contained access token builder.
 */
public class JWTTokenIssuer extends OauthTokenIssuerImpl {

    // Signature algorithms.
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

    private static final String AUTHORIZATION_PARTY = "azp";
    private static final String AUDIENCE = "aud";
    private static final String SCOPE = "scope";
    private static final String TOKEN_BINDING_REF = "binding_ref";
    private static final String TOKEN_BINDING_TYPE = "binding_type";

    private static final Log log = LogFactory.getLog(JWTTokenIssuer.class);
    private static final String INBOUND_AUTH2_TYPE = "oauth2";
    private Algorithm signatureAlgorithm = null;

    public JWTTokenIssuer() throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("JWT Access token builder is initiated");
        }

        OAuthServerConfiguration config = OAuthServerConfiguration.getInstance();

        // Map signature algorithm from identity.xml to nimbus format, this is a one time configuration.
        signatureAlgorithm = mapSignatureAlgorithm(config.getSignatureAlgorithm());
    }

    @Override
    public String accessToken(OAuthTokenReqMessageContext oAuthTokenReqMessageContext) throws OAuthSystemException {

        if (log.isDebugEnabled()) {
            log.debug("Access token request with token request message context. Authorized user " +
                    oAuthTokenReqMessageContext.getAuthorizedUser().getLoggableUserId());
        }

        try {
            return this.buildJWTToken(oAuthTokenReqMessageContext);
        } catch (IdentityOAuth2Exception e) {
            throw new OAuthSystemException(e);
        }
    }

    @Override
    public String accessToken(OAuthAuthzReqMessageContext oAuthAuthzReqMessageContext) throws OAuthSystemException {

        if (log.isDebugEnabled()) {
            log.debug("Access token request with authorization request message context message context. Authorized " +
                    "user " + oAuthAuthzReqMessageContext.getAuthorizationReqDTO().getUser().getLoggableUserId());
        }

        try {
            return this.buildJWTToken(oAuthAuthzReqMessageContext);
        } catch (IdentityOAuth2Exception e) {
            throw new OAuthSystemException(e);
        }
    }

    @Override
    public String getAccessTokenHash(String accessToken) throws OAuthSystemException {
        try {
            JWT parsedJwtToken = JWTParser.parse(accessToken);
            String jwtId = parsedJwtToken.getJWTClaimsSet().getJWTID();
            if (jwtId == null) {
                throw new OAuthSystemException("JTI could not be retrieved from the JWT token.");
            }
            return jwtId;
        } catch (ParseException e) {
            if (log.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                log.debug("Error while getting JWTID from token: " + accessToken);
            }
            throw new OAuthSystemException("Error while getting access token hash", e);
        }
    }

    @Override
    public boolean renewAccessTokenPerRequest() {
        return true;
    }

    /**
     * Build a signed jwt token from OauthToken request message context.
     *
     * @param request Token request message context.
     * @return Signed jwt string.
     * @throws IdentityOAuth2Exception
     */
    protected String buildJWTToken(OAuthTokenReqMessageContext request) throws IdentityOAuth2Exception {

        // Set claims to jwt token.
        JWTClaimsSet jwtClaimsSet = createJWTClaimSet(null, request, request.getOauth2AccessTokenReqDTO()
                .getClientId());
        JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder(jwtClaimsSet);

        if (request.getScope() != null && Arrays.asList((request.getScope())).contains(AUDIENCE)) {
            jwtClaimsSetBuilder.audience(Arrays.asList(request.getScope()));
        }
        jwtClaimsSet = jwtClaimsSetBuilder.build();
        if (JWSAlgorithm.NONE.getName().equals(signatureAlgorithm.getName())) {
            return new PlainJWT(jwtClaimsSet).serialize();
        }

        return signJWT(jwtClaimsSet, request, null);
    }

    /**
     * Build a signed jwt token from authorization request message context.
     *
     * @param request Oauth authorization message context.
     * @return Signed jwt string.
     * @throws IdentityOAuth2Exception
     */
    protected String buildJWTToken(OAuthAuthzReqMessageContext request) throws IdentityOAuth2Exception {

        // Set claims to jwt token.
        JWTClaimsSet jwtClaimsSet = createJWTClaimSet(request, null, request.getAuthorizationReqDTO()
                .getConsumerKey());
        JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder(jwtClaimsSet);

        if (request.getApprovedScope() != null && Arrays.asList((request.getApprovedScope())).contains(AUDIENCE)) {
            jwtClaimsSetBuilder.audience(Arrays.asList(request.getApprovedScope()));
        }
        jwtClaimsSet = jwtClaimsSetBuilder.build();

        if (JWSAlgorithm.NONE.getName().equals(signatureAlgorithm.getName())) {
            return new PlainJWT(jwtClaimsSet).serialize();
        }

        return signJWT(jwtClaimsSet, null, request);
    }

    /**
     * Sign ghe JWT token according to the given signature signing algorithm.
     *
     * @param jwtClaimsSet         JWT claim set to be signed.
     * @param tokenContext         Token context.
     * @param authorizationContext Authorization context.
     * @return Signed JWT.
     * @throws IdentityOAuth2Exception
     */
    protected String signJWT(JWTClaimsSet jwtClaimsSet,
                             OAuthTokenReqMessageContext tokenContext,
                             OAuthAuthzReqMessageContext authorizationContext) throws IdentityOAuth2Exception {

        if (JWSAlgorithm.RS256.equals(signatureAlgorithm) || JWSAlgorithm.RS384.equals(signatureAlgorithm) ||
                JWSAlgorithm.RS512.equals(signatureAlgorithm)) {
            return signJWTWithRSA(jwtClaimsSet, tokenContext, authorizationContext);
        } else if (JWSAlgorithm.HS256.equals(signatureAlgorithm) || JWSAlgorithm.HS384.equals(signatureAlgorithm) ||
                JWSAlgorithm.HS512.equals(signatureAlgorithm)) {
            return signJWTWithHMAC(jwtClaimsSet, tokenContext, authorizationContext);
        } else if (JWSAlgorithm.ES256.equals(signatureAlgorithm) || JWSAlgorithm.ES384.equals(signatureAlgorithm) ||
                JWSAlgorithm.ES512.equals(signatureAlgorithm)) {
            return signJWTWithECDSA(jwtClaimsSet, tokenContext, authorizationContext);
        } else {
            throw new IdentityOAuth2Exception("Invalid signature algorithm provided. " + signatureAlgorithm);
        }
    }

    /**
     * Resolve the tenant domain to sign the request based on OAuthTokenReqMessageContext and
     * OAuthAuthzReqMessageContext values.
     *
     * @param tokenContext         OAuthTokenReqMessageContext.
     * @param authorizationContext OAuthAuthzReqMessageContext.
     * @return Tenant domain to sign the request.
     * @throws IdentityOAuth2Exception If an error occurred while resolving the tenant domain.
     */
    private String resolveSigningTenantDomain(OAuthTokenReqMessageContext tokenContext,
                                              OAuthAuthzReqMessageContext authorizationContext)
            throws IdentityOAuth2Exception {

        String clientID;
        AuthenticatedUser authenticatedUser;
        if (authorizationContext != null) {
            clientID = authorizationContext.getAuthorizationReqDTO().getConsumerKey();
            authenticatedUser = authorizationContext.getAuthorizationReqDTO().getUser();
        } else if (tokenContext != null) {
            clientID = tokenContext.getOauth2AccessTokenReqDTO().getClientId();
            authenticatedUser = tokenContext.getAuthorizedUser();
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Empty OAuthTokenReqMessageContext and OAuthAuthzReqMessageContext. Therefore, could " +
                        "not determine the tenant domain to sign the request.");
            }
            throw new IdentityOAuth2Exception("Could not determine the authenticated user and the service provider");
        }
        return getSigningTenantDomain(clientID, authenticatedUser);
    }

    /**
     * Get the tenant domain to sign the the token.
     *
     * @param clientID          Client Id.
     * @param authenticatedUser Authenticated user.
     * @return Tenant domain to sign thee token.
     * @throws IdentityOAuth2Exception If an error occurred while getting the application information by client id.
     */
    private String getSigningTenantDomain(String clientID, AuthenticatedUser authenticatedUser)
            throws IdentityOAuth2Exception {

        String tenantDomain;
        if (OAuthServerConfiguration.getInstance().getUseSPTenantDomainValue()) {
            if (log.isDebugEnabled()) {
                log.debug("Using the tenant domain of the SP to sign the token");
            }
            if (StringUtils.isBlank(clientID)) {
                throw new IdentityOAuth2Exception("Empty ClientId. Cannot resolve the tenant domain to sign the token");
            }
            try {
                tenantDomain = OAuth2Util.getAppInformationByClientId(clientID).getAppOwner().getTenantDomain();
            } catch (InvalidOAuthClientException e) {
                throw new IdentityOAuth2Exception("Error occurred while getting the application information by client" +
                        " id: " + clientID, e);
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Using the tenant domain of the user to sign the token");
            }
            if (authenticatedUser == null) {
                throw new IdentityOAuth2Exception(
                        "Authenticated user is not set. Cannot resolve the tenant domain to sign the token");
            }
            tenantDomain = authenticatedUser.getTenantDomain();
        }
        if (StringUtils.isBlank(tenantDomain)) {
            throw new IdentityOAuth2Exception("Cannot resolve the tenant domain to sign the token");
        }
        if (log.isDebugEnabled()) {
            log.debug(String.format("Tenant domain: %s will be used to sign the token for the authenticated " +
                    "user: %s", tenantDomain, authenticatedUser.toFullQualifiedUsername()));
        }
        return tenantDomain;
    }

    /**
     * Sign the JWT token with RSA (SHA-256, SHA-384, SHA-512) algorithm.
     *
     * @param jwtClaimsSet         JWT claim set to be signed.
     * @param tokenContext         Token context if available.
     * @param authorizationContext Authorization context if available.
     * @return Signed JWT token.
     * @throws IdentityOAuth2Exception
     */
    protected String signJWTWithRSA(JWTClaimsSet jwtClaimsSet, OAuthTokenReqMessageContext tokenContext,
                                    OAuthAuthzReqMessageContext authorizationContext) throws IdentityOAuth2Exception {

        try {
            String tenantDomain = resolveSigningTenantDomain(tokenContext, authorizationContext);
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);

            Key privateKey = getPrivateKey(tenantDomain, tenantId);
            JWSSigner signer = OAuth2Util.createJWSSigner((RSAPrivateKey) privateKey);
            JWSHeader.Builder headerBuilder = new JWSHeader.Builder((JWSAlgorithm) signatureAlgorithm);
            String certThumbPrint = OAuth2Util.getThumbPrint(tenantDomain, tenantId);
            headerBuilder.keyID(OAuth2Util.getKID(OAuth2Util.getCertificate(tenantDomain, tenantId),
                    (JWSAlgorithm) signatureAlgorithm, tenantDomain));
            headerBuilder.x509CertThumbprint(new Base64URL(certThumbPrint));
            SignedJWT signedJWT = new SignedJWT(headerBuilder.build(), jwtClaimsSet);
            signedJWT.sign(signer);
            return signedJWT.serialize();
        } catch (JOSEException e) {
            throw new IdentityOAuth2Exception("Error occurred while signing JWT", e);
        }
    }

    // TODO: Implement JWT signing with HMAC SHA (SHA-256, SHA-384, SHA-512).
    protected String signJWTWithHMAC(JWTClaimsSet jwtClaimsSet,
                                     OAuthTokenReqMessageContext tokenContext,
                                     OAuthAuthzReqMessageContext authorizationContext) throws IdentityOAuth2Exception {

        throw new IdentityOAuth2Exception("Given signature algorithm " + signatureAlgorithm + " is not supported " +
                "by the current implementation.");
    }

    // TODO: Implement JWT signing with ECDSA (SHA-256, SHA-384, SHA-512).
    protected String signJWTWithECDSA(JWTClaimsSet jwtClaimsSet,
                                      OAuthTokenReqMessageContext tokenContext,
                                      OAuthAuthzReqMessageContext authorizationContext) throws IdentityOAuth2Exception {

        throw new IdentityOAuth2Exception("Given signature algorithm " + signatureAlgorithm + " is not supported " +
                "by the current implementation.");
    }

    /**
     * This method map signature algorithm define in identity.xml to nimbus signature algorithm format, Strings are
     * defined inline hence there are not being used any where
     *
     * @param signatureAlgorithm Signature algorithm.
     * @return JWS algorithm.
     * @throws IdentityOAuth2Exception Unsupported signature algorithm.
     */
    protected JWSAlgorithm mapSignatureAlgorithm(String signatureAlgorithm) throws IdentityOAuth2Exception {

        if (StringUtils.isNotBlank(signatureAlgorithm)) {
            switch (signatureAlgorithm) {
                case NONE:
                    return new JWSAlgorithm(JWSAlgorithm.NONE.getName());
                case SHA256_WITH_RSA:
                    return JWSAlgorithm.RS256;
                case SHA384_WITH_RSA:
                    return JWSAlgorithm.RS384;
                case SHA512_WITH_RSA:
                    return JWSAlgorithm.RS512;
                case SHA256_WITH_HMAC:
                    return JWSAlgorithm.HS256;
                case SHA384_WITH_HMAC:
                    return JWSAlgorithm.HS384;
                case SHA512_WITH_HMAC:
                    return JWSAlgorithm.HS512;
                case SHA256_WITH_EC:
                    return JWSAlgorithm.ES256;
                case SHA384_WITH_EC:
                    return JWSAlgorithm.ES384;
                case SHA512_WITH_EC:
                    return JWSAlgorithm.ES512;
            }
        }

        throw new IdentityOAuth2Exception("Unsupported Signature Algorithm in identity.xml");
    }

    /**
     * Create a JWT claim set according to the JWT format.
     *
     * @param authAuthzReqMessageContext Oauth authorization request message context.
     * @param tokenReqMessageContext     Token request message context.
     * @param consumerKey                Consumer key of the application.
     * @return JWT claim set.
     * @throws IdentityOAuth2Exception
     */
    protected JWTClaimsSet createJWTClaimSet(OAuthAuthzReqMessageContext authAuthzReqMessageContext,
                                             OAuthTokenReqMessageContext tokenReqMessageContext,
                                             String consumerKey) throws IdentityOAuth2Exception {

        // loading the stored application data
        OAuthAppDO oAuthAppDO;
        try {
            oAuthAppDO = OAuth2Util.getAppInformationByClientId(consumerKey);
        } catch (InvalidOAuthClientException e) {
            throw new IdentityOAuth2Exception("Error while retrieving app information for clientId: " + consumerKey, e);
        }

        AuthenticatedUser user;
        String spTenantDomain;
        long accessTokenLifeTimeInMillis;
        if (authAuthzReqMessageContext != null) {
            accessTokenLifeTimeInMillis =
                    getAccessTokenLifeTimeInMillis(authAuthzReqMessageContext, oAuthAppDO, consumerKey);
            spTenantDomain = authAuthzReqMessageContext.getAuthorizationReqDTO().getTenantDomain();
        } else {
            accessTokenLifeTimeInMillis =
                    getAccessTokenLifeTimeInMillis(tokenReqMessageContext, oAuthAppDO, consumerKey);
            spTenantDomain = tokenReqMessageContext.getOauth2AccessTokenReqDTO().getTenantDomain();
        }

        String issuer = OAuth2Util.getIdTokenIssuer(spTenantDomain);
        long curTimeInMillis = Calendar.getInstance().getTimeInMillis();

        AuthenticatedUser authenticatedUser = getAuthenticatedUser(authAuthzReqMessageContext, tokenReqMessageContext);
        String sub = getSubjectClaim(consumerKey, spTenantDomain, authenticatedUser);

        // Set the default claims.
        JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
        jwtClaimsSetBuilder.issuer(issuer);
        jwtClaimsSetBuilder.subject(sub);
        jwtClaimsSetBuilder.claim(AUTHORIZATION_PARTY, consumerKey);
        jwtClaimsSetBuilder.issueTime(new Date(curTimeInMillis));
        jwtClaimsSetBuilder.jwtID(UUID.randomUUID().toString());
        jwtClaimsSetBuilder.notBeforeTime(new Date(curTimeInMillis));

        String scope = getScope(authAuthzReqMessageContext, tokenReqMessageContext);
        if (StringUtils.isNotEmpty(scope)) {
            jwtClaimsSetBuilder.claim(SCOPE, scope);
        }

        jwtClaimsSetBuilder.claim(OAuthConstants.AUTHORIZED_USER_TYPE,
                getAuthorizedUserType(authAuthzReqMessageContext, tokenReqMessageContext));

        jwtClaimsSetBuilder.expirationTime(calculateAccessTokenExpiryTime(accessTokenLifeTimeInMillis,
                curTimeInMillis));

        // This is a spec (openid-connect-core-1_0:2.0) requirement for ID tokens. But we are keeping this in JWT
        // as well.
        List<String> audience = OAuth2Util.getOIDCAudience(consumerKey, oAuthAppDO);
        jwtClaimsSetBuilder.audience(audience);
        JWTClaimsSet jwtClaimsSet;

        // Handle custom claims
        if (authAuthzReqMessageContext != null) {
            jwtClaimsSet = handleCustomClaims(jwtClaimsSetBuilder, authAuthzReqMessageContext);
        } else {
            jwtClaimsSet = handleCustomClaims(jwtClaimsSetBuilder, tokenReqMessageContext);
        }
        // Include token binding.
        jwtClaimsSet = handleTokenBinding(jwtClaimsSetBuilder, tokenReqMessageContext);

        return jwtClaimsSet;
    }

    /**
     * Calculates access token expiry time.
     *
     * @param accessTokenLifeTimeInMillis accessTokenLifeTimeInMillis
     * @param curTimeInMillis             currentTimeInMillis
     * @return expirationTime
     */
    private Date calculateAccessTokenExpiryTime(Long accessTokenLifeTimeInMillis, Long curTimeInMillis) {

        Date expirationTime;
        if (accessTokenLifeTimeInMillis < 0) {
            if (log.isDebugEnabled()) {
                log.debug("Infinite access token expiry detected. Setting the expiry value to MAX value: " +
                        Long.MAX_VALUE + "ms.");
            }
            // Expiry time set to MAX value as (current + MAX) will lead to a negative value.
            expirationTime = new Date(Long.MAX_VALUE);
        } else {
            expirationTime = new Date(curTimeInMillis + accessTokenLifeTimeInMillis);
        }
        if (log.isDebugEnabled()) {
            log.debug("Access token expiry time : " + expirationTime + "ms.");
        }
        return expirationTime;
    }

    private String getAuthorizedUserType(OAuthAuthzReqMessageContext authAuthzReqMessageContext,
                                         OAuthTokenReqMessageContext tokenReqMessageContext) {

        if (tokenReqMessageContext != null) {
            return (String) tokenReqMessageContext.getProperty(OAuthConstants.UserType.USER_TYPE);
        } else {
            return (String) authAuthzReqMessageContext.getProperty(OAuthConstants.UserType.USER_TYPE);
        }
    }

    /**
     * To get authenticated subject identifier.
     *
     * @param authAuthzReqMessageContext Auth Request Message Context.
     * @param tokenReqMessageContext     Token request message context.
     * @return authenticated subject identifier.
     */
    private String getAuthenticatedSubjectIdentifier(OAuthAuthzReqMessageContext authAuthzReqMessageContext,
            OAuthTokenReqMessageContext tokenReqMessageContext) throws IdentityOAuth2Exception {

        AuthenticatedUser authenticatedUser = getAuthenticatedUser(authAuthzReqMessageContext, tokenReqMessageContext);
        return authenticatedUser.getAuthenticatedSubjectIdentifier();
    }

    private String getSubjectClaim(String clientId, String spTenantDomain, AuthenticatedUser authorizedUser)
            throws IdentityOAuth2Exception {

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
            try {
                subjectClaim = authorizedUser.getUserId();
            } catch (UserIdNotFoundException e) {
                throw new IdentityOAuth2Exception("User id not found for user: " + authorizedUser.getLoggableUserId(),
                        e);
            }
            if (log.isDebugEnabled()) {
                log.debug("Subject claim: " + subjectClaim + " set for federated user: " + authorizedUser + " for " +
                        "application: " + clientId + " of tenantDomain: " + spTenantDomain);
            }
        }
        return subjectClaim;
    }

    private ServiceProvider getServiceProvider(String spTenantDomain,
                                               String clientId) throws IdentityOAuth2Exception {

        ApplicationManagementService applicationMgtService = OAuth2ServiceComponentHolder.getApplicationMgtService();
        try {
            String spName = applicationMgtService.getServiceProviderNameByClientId(clientId, INBOUND_AUTH2_TYPE,
                    spTenantDomain);
            return applicationMgtService.getApplicationExcludingFileBasedSPs(spName, spTenantDomain);
        } catch (IdentityApplicationManagementException e) {
            throw new IdentityOAuth2Exception("Error while getting service provider information for client_id: "
                    + clientId + " tenantDomain: " + spTenantDomain, e);
        }
    }

    private boolean isLocalUser(AuthenticatedUser authorizedUser) {

        return !authorizedUser.isFederatedUser();
    }

    private String getSubjectClaimForLocalUser(ServiceProvider serviceProvider,
                                               AuthenticatedUser authorizedUser) throws IdentityOAuth2Exception {

        String subject;
        String userStoreDomain = authorizedUser.getUserStoreDomain();
        String userTenantDomain = authorizedUser.getTenantDomain();

        String subjectClaimUri = getSubjectClaimUriInLocalDialect(serviceProvider);
        if (StringUtils.isNotBlank(subjectClaimUri)) {
            String fullQualifiedUsername = authorizedUser.toFullQualifiedUsername();
            try {
                subject = getSubjectClaimFromUserStore(subjectClaimUri, authorizedUser);
                if (StringUtils.isBlank(subject)) {
                    // Set username as the subject claim since we have no other option
                    subject = authorizedUser.getUserId();
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
            try {
                subject = getFormattedSubjectClaim(serviceProvider, authorizedUser.getUserId(), userStoreDomain,
                        userTenantDomain);
            } catch (UserIdNotFoundException e) {
                throw new IdentityOAuth2Exception("User id not found for user: " + authorizedUser.getLoggableUserId(),
                        e);
            }
            if (log.isDebugEnabled()) {
                log.debug("No subject claim defined for service provider: " + serviceProvider.getApplicationName()
                        + ". Using username as the subject claim.");
            }

        }
        return subject;
    }

    private String getFormattedSubjectClaim(ServiceProvider serviceProvider, String subjectClaimValue,
                                            String userStoreDomain, String tenantDomain) {

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

    private String getSubjectClaimFromUserStore(String subjectClaimUri, AuthenticatedUser authenticatedUser)
            throws UserStoreException, IdentityException {

        AbstractUserStoreManager userStoreManager = (AbstractUserStoreManager) IdentityTenantUtil
                .getRealm(authenticatedUser.getTenantDomain(), authenticatedUser.toFullQualifiedUsername())
                .getUserStoreManager();

        return userStoreManager
                .getUserClaimValueWithID(authenticatedUser.getUserId(), subjectClaimUri, null);
    }

    /**
     * Get authentication request object from message context
     *
     * @param authAuthzReqMessageContext
     * @param tokenReqMessageContext
     *
     * @return AuthenticatedUser
     */
    private AuthenticatedUser getAuthenticatedUser(OAuthAuthzReqMessageContext authAuthzReqMessageContext,
                                                   OAuthTokenReqMessageContext tokenReqMessageContext)
            throws IdentityOAuth2Exception {
        AuthenticatedUser authenticatedUser;
        if (authAuthzReqMessageContext != null) {
            authenticatedUser = authAuthzReqMessageContext.getAuthorizationReqDTO().getUser();
        } else {
            authenticatedUser = tokenReqMessageContext.getAuthorizedUser();
        }

        if (authenticatedUser == null) {
            throw new IdentityOAuth2Exception("Authenticated user is null for the request.");
        }
        return authenticatedUser;
    }

    /**
     * To get the scope of the token to be added to the JWT claims.
     *
     * @param authAuthzReqMessageContext Auth Request Message Context.
     * @param tokenReqMessageContext     Token Request Message Context.
     * @return scope of token.
     */
    private String getScope(OAuthAuthzReqMessageContext authAuthzReqMessageContext,
            OAuthTokenReqMessageContext tokenReqMessageContext) throws IdentityOAuth2Exception {

        String[] scope;
        String scopeString = null;
        if (tokenReqMessageContext != null) {
            scope = tokenReqMessageContext.getScope();
        } else {
            scope = authAuthzReqMessageContext.getApprovedScope();
        }
        if (ArrayUtils.isNotEmpty(scope)) {
            scopeString = OAuth2Util.buildScopeString(scope);
            if (log.isDebugEnabled()) {
                log.debug("Scope exist for the jwt access token with subject " + getAuthenticatedSubjectIdentifier(
                        authAuthzReqMessageContext, tokenReqMessageContext) + " and the scope is " + scopeString);
            }
        }
        return scopeString;
    }

    /**
     * Get token validity period for the Self contained JWT Access Token. (For implicit grant)
     *
     * @param authzReqMessageContext
     * @param oAuthAppDO
     * @param consumerKey
     * @return
     * @throws IdentityOAuth2Exception
     */
    protected long getAccessTokenLifeTimeInMillis(OAuthAuthzReqMessageContext authzReqMessageContext,
                                                  OAuthAppDO oAuthAppDO,
                                                  String consumerKey) throws IdentityOAuth2Exception {
        long lifetimeInMillis = oAuthAppDO.getUserAccessTokenExpiryTime() * 1000;
        if (lifetimeInMillis == 0) {
            lifetimeInMillis = OAuthServerConfiguration.getInstance()
                    .getUserAccessTokenValidityPeriodInSeconds() * 1000;
            if (log.isDebugEnabled()) {
                log.debug("User access token time was 0ms. Setting default user access token lifetime : "
                        + lifetimeInMillis + "ms.");
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("JWT Self Signed Access Token Life time set to : " + lifetimeInMillis + "ms.");
        }
        return lifetimeInMillis;
    }

    /**
     * Get token validity period for the Self contained JWT Access Token.
     *
     * @param tokenReqMessageContext
     * @param oAuthAppDO
     * @param consumerKey
     * @return
     * @throws IdentityOAuth2Exception
     */
    protected long getAccessTokenLifeTimeInMillis(OAuthTokenReqMessageContext tokenReqMessageContext,
                                                  OAuthAppDO oAuthAppDO,
                                                  String consumerKey) throws IdentityOAuth2Exception {
        long lifetimeInMillis;
        boolean isUserAccessTokenType =
                isUserAccessTokenType(tokenReqMessageContext.getOauth2AccessTokenReqDTO().getGrantType());

        if (isUserAccessTokenType) {
            lifetimeInMillis = oAuthAppDO.getUserAccessTokenExpiryTime() * 1000;
            if (log.isDebugEnabled()) {
                log.debug("User Access Token Life time set to : " + lifetimeInMillis + "ms.");
            }
        } else {
            lifetimeInMillis = oAuthAppDO.getApplicationAccessTokenExpiryTime() * 1000;
            if (log.isDebugEnabled()) {
                log.debug("Application Access Token Life time set to : " + lifetimeInMillis + "ms.");
            }
        }

        if (lifetimeInMillis == 0) {
            if (isUserAccessTokenType) {
                lifetimeInMillis =
                        OAuthServerConfiguration.getInstance().getUserAccessTokenValidityPeriodInSeconds() * 1000;
                if (log.isDebugEnabled()) {
                    log.debug("User access token time was 0ms. Setting default user access token lifetime : "
                            + lifetimeInMillis + "ms.");
                }
            } else {
                lifetimeInMillis =
                        OAuthServerConfiguration.getInstance().getApplicationAccessTokenValidityPeriodInSeconds() *
                                1000;
                if (log.isDebugEnabled()) {
                    log.debug("Application access token time was 0ms. Setting default Application access token " +
                            "lifetime : " + lifetimeInMillis + "ms.");
                }
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("JWT Self Signed Access Token Life time set to : " + lifetimeInMillis + "ms.");
        }
        return lifetimeInMillis;
    }

    /**
     * Populate custom claims (For implicit grant)
     *
     * @param jwtClaimsSetBuilder
     * @param tokenReqMessageContext
     * @throws IdentityOAuth2Exception
     */
    protected JWTClaimsSet handleCustomClaims(JWTClaimsSet.Builder jwtClaimsSetBuilder,
                                              OAuthTokenReqMessageContext tokenReqMessageContext)
            throws IdentityOAuth2Exception {

        CustomClaimsCallbackHandler claimsCallBackHandler =
                OAuthServerConfiguration.getInstance().getOpenIDConnectCustomClaimsCallbackHandler();
        return claimsCallBackHandler.handleCustomClaims(jwtClaimsSetBuilder, tokenReqMessageContext);
    }

    /**
     * Populate custom claims
     *
     * @param jwtClaimsSetBuilder
     * @param authzReqMessageContext
     * @throws IdentityOAuth2Exception
     */
    protected JWTClaimsSet handleCustomClaims(JWTClaimsSet.Builder jwtClaimsSetBuilder,
                                              OAuthAuthzReqMessageContext authzReqMessageContext)
            throws IdentityOAuth2Exception {

        CustomClaimsCallbackHandler claimsCallBackHandler =
                OAuthServerConfiguration.getInstance().getOpenIDConnectCustomClaimsCallbackHandler();
        return claimsCallBackHandler.handleCustomClaims(jwtClaimsSetBuilder, authzReqMessageContext);
    }


    private boolean isUserAccessTokenType(String grantType) throws IdentityOAuth2Exception {
        AuthorizationGrantHandler grantHandler =
                OAuthServerConfiguration.getInstance().getSupportedGrantTypes().get(grantType);
        // If grant handler is null ideally we would not come to this point as the flow will be broken before. So we
        // can guarantee grantHandler will not be null
        return grantHandler.isOfTypeApplicationUser();
    }

    private JWTClaimsSet handleTokenBinding(JWTClaimsSet.Builder jwtClaimsSetBuilder,
                                            OAuthTokenReqMessageContext tokReqMsgCtx) {

        if (tokReqMsgCtx != null && tokReqMsgCtx.getTokenBinding() != null) {
            // Include token binding into the jwt token.
            jwtClaimsSetBuilder.claim(TOKEN_BINDING_REF, tokReqMsgCtx.getTokenBinding().getBindingReference());
            jwtClaimsSetBuilder.claim(TOKEN_BINDING_TYPE, tokReqMsgCtx.getTokenBinding().getBindingType());
        }
        return jwtClaimsSetBuilder.build();
    }
}
