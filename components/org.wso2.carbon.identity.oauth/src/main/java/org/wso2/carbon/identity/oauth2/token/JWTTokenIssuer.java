/*
 * Copyright (c) 2017-2025, WSO2 LLC. (http://www.wso2.com).
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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.token;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
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
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.OAuth2Constants;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinding;
import org.wso2.carbon.identity.oauth2.token.handlers.claims.JWTAccessTokenClaimProvider;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AuthorizationGrantHandler;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.CustomClaimsCallbackHandler;
import org.wso2.carbon.identity.openidconnect.DefaultIDTokenBuilder;
import org.wso2.carbon.identity.openidconnect.OIDCClaimUtil;
import org.wso2.carbon.identity.openidconnect.util.ClaimHandlerUtil;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;

import java.security.Key;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCClaims.AUTH_TIME;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCConfigProperties.SUBJECT_TOKEN_EXPIRY_TIME_VALUE;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.RENEW_TOKEN_WITHOUT_REVOKING_EXISTING_ENABLE_CONFIG;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.REQUEST_BINDING_TYPE;
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
    private static final String PS256 = "PS256";
    private static final String SHA256_WITH_HMAC = "SHA256withHMAC";
    private static final String SHA384_WITH_HMAC = "SHA384withHMAC";
    private static final String SHA512_WITH_HMAC = "SHA512withHMAC";
    private static final String SHA256_WITH_EC = "SHA256withEC";
    private static final String SHA384_WITH_EC = "SHA384withEC";
    private static final String SHA512_WITH_EC = "SHA512withEC";

    private static final String AUTHORIZATION_PARTY = "azp";
    private static final String CLIENT_ID = "client_id";
    private static final String AUDIENCE = "aud";
    private static final String SCOPE = "scope";
    private static final String TOKEN_BINDING_REF = "binding_ref";
    private static final String TOKEN_BINDING_TYPE = "binding_type";
    private static final String DEFAULT_TYP_HEADER_VALUE = "at+jwt";
    private static final String CNF = "cnf";
    private static final Log log = LogFactory.getLog(JWTTokenIssuer.class);
    private static final String INBOUND_AUTH2_TYPE = "oauth2";
    private Algorithm signatureAlgorithm = null;
    private static final String ENABLE_PPID_FOR_ACCESS_TOKENS = "OAuth.OpenIDConnect.EnablePairwiseSubForAccessToken";
    private static final String JWT_TYP_HEADER_VALUE = "jwt";
    private static final String MAY_ACT = "may_act";
    private static final String SUB = "sub";
    private static final String AUTHORIZATION_CODE = "AuthorizationCode";
    private static final String PREVIOUS_ACCESS_TOKEN = "previousAccessToken";

    public JWTTokenIssuer() throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("JWT Access token builder is initiated");
        }

        OAuthServerConfiguration config = OAuthServerConfiguration.getInstance();

        // Map signature algorithm from identity.xml to nimbus format, this is a one time configuration.
        signatureAlgorithm = mapSignatureAlgorithm(config.getSignatureAlgorithm());
    }

    @Override
    public String getAccessTokenType() {

        return JWT_TYP_HEADER_VALUE;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String issueSubjectToken(OAuthAuthzReqMessageContext oauthAuthzMsgCtx) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Subject token request with authorization request message context message context. " +
                    "Authorized user " + oauthAuthzMsgCtx.getAuthorizationReqDTO().getUser().getLoggableUserId());
        }

        return this.buildSubjectJWTToken(oauthAuthzMsgCtx);
    }

    private String buildSubjectJWTToken(OAuthAuthzReqMessageContext oauthAuthzMsgCtx) throws IdentityOAuth2Exception {

        JWTClaimsSet jwtClaimsSet = createSubjectTokenJWTClaimSet(oauthAuthzMsgCtx);
        JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder(jwtClaimsSet);
        jwtClaimsSet = jwtClaimsSetBuilder.build();

        if (JWSAlgorithm.NONE.getName().equals(signatureAlgorithm.getName())) {
            return new PlainJWT(jwtClaimsSet).serialize();
        }
        return signJWT(jwtClaimsSet, null, oauthAuthzMsgCtx);
    }

    private JWTClaimsSet createSubjectTokenJWTClaimSet(OAuthAuthzReqMessageContext oauthAuthzMsgCtx)
            throws IdentityOAuth2Exception {

        String consumerKey = oauthAuthzMsgCtx.getAuthorizationReqDTO().getConsumerKey();
        // loading the stored application data
        OAuthAppDO oAuthAppDO;
        try {
            oAuthAppDO = OAuth2Util.getAppInformationByClientId(consumerKey);
        } catch (InvalidOAuthClientException e) {
            throw new IdentityOAuth2Exception("Error while retrieving app information for clientId: " + consumerKey, e);
        }

        String spTenantDomain = oauthAuthzMsgCtx.getAuthorizationReqDTO().getTenantDomain();
        if (oAuthAppDO.getSubjectTokenExpiryTime() <= 0) {
            oAuthAppDO.setSubjectTokenExpiryTime(SUBJECT_TOKEN_EXPIRY_TIME_VALUE);
        }
        int subjectTokenLifeTimeInSec = oAuthAppDO.getSubjectTokenExpiryTime() * 1000;;

        String issuer = OAuth2Util.getIdTokenIssuer(spTenantDomain);
        long curTimeInMillis = Calendar.getInstance().getTimeInMillis();

        AuthenticatedUser authenticatedUser = getAuthenticatedUser(oauthAuthzMsgCtx, null);
        String sub = authenticatedUser.getAuthenticatedSubjectIdentifier();

        String subject = oauthAuthzMsgCtx.getAuthorizationReqDTO().getRequestedSubjectId();

        // Set the default claims.
        JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
        jwtClaimsSetBuilder.issuer(issuer);
        jwtClaimsSetBuilder.subject(subject);
        String scope = getScope(oauthAuthzMsgCtx, null);
        if (StringUtils.isNotEmpty(scope)) {
            jwtClaimsSetBuilder.claim(SCOPE, scope);
        }

        jwtClaimsSetBuilder.claim(AUTHORIZATION_PARTY, consumerKey);
        jwtClaimsSetBuilder.issueTime(new Date(curTimeInMillis));
        jwtClaimsSetBuilder.jwtID(UUID.randomUUID().toString());
        jwtClaimsSetBuilder.notBeforeTime(new Date(curTimeInMillis));
        jwtClaimsSetBuilder.claim(CLIENT_ID, consumerKey);

        jwtClaimsSetBuilder.claim(MAY_ACT, Collections.singletonMap(SUB, sub));
        jwtClaimsSetBuilder.expirationTime(calculateSubjectTokenExpiryTime(subjectTokenLifeTimeInSec,
                curTimeInMillis));
        List<String> audience = OAuth2Util.getOIDCAudience(consumerKey, oAuthAppDO);
        jwtClaimsSetBuilder.audience(audience);

        return jwtClaimsSetBuilder.build();
    }

    private Date calculateSubjectTokenExpiryTime(long subjectTokenLifeTimeInMillis, long curTimeInMillis) {

        Date expirationTime =  new Date(curTimeInMillis + subjectTokenLifeTimeInMillis);

        if (log.isDebugEnabled()) {
            log.debug("Subject token expiry time : " + expirationTime + "ms.");
        }
        return expirationTime;
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

        if (StringUtils.isBlank(accessToken)) {
            throw new OAuthSystemException("Token should not be empty or null.");
        }

        try {
            JWT parsedJwtToken = JWTParser.parse(accessToken);
            // JWT ClaimsSet can be null if the ID token is encrypted.
            if (parsedJwtToken.getJWTClaimsSet() == null) {
                throw new OAuthSystemException("JWT claims set is null in the JWT token.");
            }
            String jwtId = parsedJwtToken.getJWTClaimsSet().getJWTID();
            if (StringUtils.isBlank(jwtId)) {
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

        List<JWTAccessTokenClaimProvider> claimProviders = getJWTAccessTokenClaimProviders();
        for (JWTAccessTokenClaimProvider claimProvider : claimProviders) {
            Map<String, Object> additionalClaims = claimProvider.getAdditionalClaims(request);
            if (additionalClaims != null) {
                additionalClaims.forEach(jwtClaimsSetBuilder::claim);
            }
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

        List<JWTAccessTokenClaimProvider> claimProviders = getJWTAccessTokenClaimProviders();
        for (JWTAccessTokenClaimProvider claimProvider : claimProviders) {
            Map<String, Object> additionalClaims = claimProvider.getAdditionalClaims(request);
            if (additionalClaims != null) {
                additionalClaims.forEach(jwtClaimsSetBuilder::claim);
            }
        }

        jwtClaimsSet = jwtClaimsSetBuilder.build();

        if (JWSAlgorithm.NONE.getName().equals(signatureAlgorithm.getName())) {
            return new PlainJWT(jwtClaimsSet).serialize();
        }

        return signJWT(jwtClaimsSet, null, request);
    }

    private static List<JWTAccessTokenClaimProvider> getJWTAccessTokenClaimProviders() {

        return OAuth2ServiceComponentHolder.getInstance().getJWTAccessTokenClaimProviders();
    }

    /**
     * Sign the JWT token according to the given signature signing algorithm.
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
                JWSAlgorithm.RS512.equals(signatureAlgorithm) || JWSAlgorithm.PS256.equals(signatureAlgorithm)) {
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
     * Get the tenant domain to sign the token.
     *
     * @param clientID          Client Id.
     * @param authenticatedUser Authenticated user.
     * @return Tenant domain to sign the token.
     * @throws IdentityOAuth2Exception If an error occurred while getting the application information by client id.
     */
    private String getSigningTenantDomain(String clientID, AuthenticatedUser authenticatedUser)
            throws IdentityOAuth2Exception {

        String tenantDomain;
        String applicationResidentOrgId = PrivilegedCarbonContext.getThreadLocalCarbonContext()
                .getApplicationResidentOrganizationId();
        /*
         If applicationResidentOrgId is not empty, then the request comes for an application which is registered
         directly in the organization of the applicationResidentOrgId. In this scenario, the signing tenant domain
         should be the root tenant domain of the applicationResidentOrgId.
        */
        if (StringUtils.isNotEmpty(applicationResidentOrgId)) {
            tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        } else if (OAuthServerConfiguration.getInstance().getUseSPTenantDomainValue()) {
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

            // Add claim with signer tenant to jwt claims set.
            jwtClaimsSet = setSignerRealm(tenantDomain, jwtClaimsSet);

            Key privateKey = getPrivateKey(tenantDomain, tenantId);
            JWSSigner signer = OAuth2Util.createJWSSigner((RSAPrivateKey) privateKey);
            JWSHeader.Builder headerBuilder = new JWSHeader.Builder((JWSAlgorithm) signatureAlgorithm);
            Certificate certificate = OAuth2Util.getCertificate(tenantDomain, tenantId);
            String certThumbPrint = OAuth2Util.getThumbPrintWithPrevAlgorithm(certificate, false);
            headerBuilder.keyID(OAuth2Util.getKID(OAuth2Util.getCertificate(tenantDomain, tenantId),
                    (JWSAlgorithm) signatureAlgorithm, tenantDomain));

            if (authorizationContext != null && authorizationContext.isSubjectTokenFlow()) {
                headerBuilder.type(new JOSEObjectType(JWT_TYP_HEADER_VALUE));
            } else {
                // Set the required "typ" header "at+jwt" for access tokens issued by the issuer
                headerBuilder.type(new JOSEObjectType(DEFAULT_TYP_HEADER_VALUE));
            }
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
     * defined inline hence there are not being used anywhere
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
                case PS256:
                    return JWSAlgorithm.PS256;
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
        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        String applicationResidentOrgId = PrivilegedCarbonContext.getThreadLocalCarbonContext()
                .getApplicationResidentOrganizationId();

        DefaultIDTokenBuilder defaultIDTokenBuilder = new DefaultIDTokenBuilder();
        try {
            /*
             If applicationResidentOrgId is not empty, then the request comes for an application which is registered
             directly in the organization of the applicationResidentOrgId. Therefore, the tenant domain should be
             extracted from the organization id to get the information of the application.
            */
            if (StringUtils.isNotEmpty(applicationResidentOrgId)) {
                try {
                    tenantDomain = OAuth2ServiceComponentHolder.getInstance().getOrganizationManager()
                            .resolveTenantDomain(applicationResidentOrgId);
                } catch (OrganizationManagementException e) {
                    throw new IdentityOAuth2Exception("Error while resolving tenant domain from the organization id: "
                            + applicationResidentOrgId, e);
                }
            }
            oAuthAppDO = OAuth2Util.getAppInformationByClientId(consumerKey, tenantDomain);
        } catch (InvalidOAuthClientException e) {
            throw new IdentityOAuth2Exception("Error while retrieving app information for clientId: " + consumerKey, e);
        }

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

        /*
         If applicationResidentOrgId is not empty, then the request comes for an application which is registered
         directly in the organization of the applicationResidentOrgId. spTenantDomain is used to get the idTokenIssuer
         for the token. In this scenario, the tenant domain that needs to be used as the issuer is the root tenant.
        */
        if (StringUtils.isNotEmpty(applicationResidentOrgId)) {
            spTenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();;
        }

        boolean isMTLSrequest;
        if (authAuthzReqMessageContext != null) {
            /* If the auth request is originated from a request object reference(ex: PAR), then that endpoint should be
            considered when determining the audience and issuer claims. */
            Object isMTLSProp = authAuthzReqMessageContext.getProperty(OAuthConstants.IS_MTLS_REQUEST);
            isMTLSrequest = isMTLSProp != null && Boolean.parseBoolean(isMTLSProp.toString());
        } else {
            // For the token requests, the token gateway is considered when determining the issuer and the audience.
            isMTLSrequest = OAuth2Util.isMtlsRequest(tokenReqMessageContext.getOauth2AccessTokenReqDTO()
                    .getHttpServletRequestWrapper().getRequestURL().toString());
        }
        String issuer = OAuth2Util.getIdTokenIssuer(spTenantDomain, isMTLSrequest);
        long curTimeInMillis = Calendar.getInstance().getTimeInMillis();

        AuthenticatedUser authenticatedUser = getAuthenticatedUser(authAuthzReqMessageContext, tokenReqMessageContext);
        String sub = authenticatedUser.getAuthenticatedSubjectIdentifier();
        if (OAuth2Util.isPairwiseSubEnabledForAccessTokens()) {
            // pairwise sub claim is returned only if pairwise subject identifier for access tokens is enabled.
            sub = OIDCClaimUtil.getSubjectClaim(sub, oAuthAppDO);
        }

        long authTime = 0;
        String acrValue = "";
        List<String> amrValues = null;

        AuthorizationGrantCacheEntry authzGrantCacheEntry;

        // AuthorizationCode only available for authorization code grant type
        if (tokenReqMessageContext != null) {
            if (getAuthorizationCode(tokenReqMessageContext) != null) {
                authzGrantCacheEntry = getAuthorizationGrantCacheEntryFromCode
                        (getAuthorizationCode(tokenReqMessageContext));

            } else {
                authzGrantCacheEntry = getAuthorizationGrantCacheEntryFromToken
                        (getPreviousAccessToken(tokenReqMessageContext));
            }

            acrValue = authzGrantCacheEntry.getSelectedAcrValue();
            authTime = authzGrantCacheEntry.getAuthTime();
            amrValues = authzGrantCacheEntry.getAmrList();
        }

        // Set the default claims.
        JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
        jwtClaimsSetBuilder.issuer(issuer);
        jwtClaimsSetBuilder.subject(sub);
        jwtClaimsSetBuilder.claim(AUTHORIZATION_PARTY, consumerKey);
        jwtClaimsSetBuilder.issueTime(new Date(curTimeInMillis));
        jwtClaimsSetBuilder.jwtID(UUID.randomUUID().toString());
        jwtClaimsSetBuilder.notBeforeTime(new Date(curTimeInMillis));
        jwtClaimsSetBuilder.claim(CLIENT_ID, consumerKey);
        if (authTime != 0) {
            jwtClaimsSetBuilder.claim(AUTH_TIME, authTime / 1000);
        }
        if (StringUtils.isNotBlank(acrValue)) {
            jwtClaimsSetBuilder.claim(OAuthConstants.ACR, acrValue);
        }
        if (amrValues != null) {
            jwtClaimsSetBuilder.claim(OAuthConstants.AMR, defaultIDTokenBuilder.translateAmrToResponse(amrValues));
        }

        setClaimsForNonPersistence(jwtClaimsSetBuilder, authAuthzReqMessageContext, tokenReqMessageContext,
                authenticatedUser, oAuthAppDO);
        String scope = getScope(authAuthzReqMessageContext, tokenReqMessageContext);
        if (StringUtils.isNotEmpty(scope)) {
            jwtClaimsSetBuilder.claim(SCOPE, scope);
        }

        jwtClaimsSetBuilder.claim(OAuthConstants.AUTHORIZED_USER_TYPE,
                getAuthorizedUserType(authAuthzReqMessageContext, tokenReqMessageContext));
        jwtClaimsSetBuilder.expirationTime(calculateAccessTokenExpiryTime(accessTokenLifeTimeInMillis,
                curTimeInMillis));

        // This is a spec (openid-connect-core-1_0:2.0) requirement for ID tokens.
        // But we are keeping this in JWT as well.
        jwtClaimsSetBuilder.audience(tokenReqMessageContext != null && tokenReqMessageContext.getAudiences() != null ?
                tokenReqMessageContext.getAudiences() : OAuth2Util.getOIDCAudience(consumerKey, oAuthAppDO));

        JWTClaimsSet jwtClaimsSet;

        // Handle custom claims
        if (authAuthzReqMessageContext != null) {
            jwtClaimsSet = handleCustomClaims(jwtClaimsSetBuilder, authAuthzReqMessageContext, oAuthAppDO);
        } else {
            jwtClaimsSet = handleCustomClaims(jwtClaimsSetBuilder, tokenReqMessageContext, oAuthAppDO);
        }

        // todo: deprecate when pre issue access token action is ready
        if (tokenReqMessageContext != null && tokenReqMessageContext.getOauth2AccessTokenReqDTO() != null &&
                tokenReqMessageContext.getOauth2AccessTokenReqDTO().getAccessTokenExtendedAttributes() != null) {
            Map<String, String> customClaims =
                    tokenReqMessageContext.getOauth2AccessTokenReqDTO().getAccessTokenExtendedAttributes()
                            .getParameters();
            if (customClaims != null && !customClaims.isEmpty()) {
                for (Map.Entry<String, String> entry : customClaims.entrySet()) {
                    jwtClaimsSetBuilder.claim(entry.getKey(), entry.getValue());
                }
            }
        }

        // Include token binding.
        jwtClaimsSet = handleTokenBinding(jwtClaimsSetBuilder, tokenReqMessageContext);

        if (tokenReqMessageContext != null && tokenReqMessageContext.getProperty(CNF) != null) {
            jwtClaimsSet = handleCnf(jwtClaimsSetBuilder, tokenReqMessageContext);
        }

        return jwtClaimsSet;
    }

    private AuthorizationGrantCacheEntry getAuthorizationGrantCacheEntryFromCode(String authorizationCode) {

        AuthorizationGrantCacheKey authorizationGrantCacheKey = new AuthorizationGrantCacheKey(authorizationCode);
        return AuthorizationGrantCache.getInstance().getValueFromCacheByCode(authorizationGrantCacheKey);
    }

    private AuthorizationGrantCacheEntry getAuthorizationGrantCacheEntryFromToken(String accessToken) {

        AuthorizationGrantCacheKey cacheKey = new AuthorizationGrantCacheKey(accessToken);
        return AuthorizationGrantCache.getInstance().getValueFromCacheByToken(cacheKey);
    }

    private String getAuthorizationCode(OAuthTokenReqMessageContext tokenReqMsgCtxt) {

        return (String) tokenReqMsgCtxt.getProperty(AUTHORIZATION_CODE);
    }

    private String getPreviousAccessToken(OAuthTokenReqMessageContext tokenReqMsgCtxt) {

        RefreshTokenValidationDataDO refreshTokenValidationDataDO =
                (RefreshTokenValidationDataDO) tokenReqMsgCtxt.getProperty(PREVIOUS_ACCESS_TOKEN);
        return (String) refreshTokenValidationDataDO.getAccessToken();
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
        // When accessTokenLifeTimeInMillis is equal to Long.MAX_VALUE the curTimeInMillis +
        // accessTokenLifeTimeInMillis can be a negative value
        if (curTimeInMillis + accessTokenLifeTimeInMillis < curTimeInMillis) {
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

    private JWTClaimsSet handleCnf(JWTClaimsSet.Builder jwtClaimsSetBuilder,
                                   OAuthTokenReqMessageContext tokReqMsgCtx) {

        jwtClaimsSetBuilder.claim(CNF, tokReqMsgCtx.getProperty(CNF));
        return jwtClaimsSetBuilder.build();
    }

    /**
     * Get authentication request object from message context.
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

        if (tokenReqMessageContext.isPreIssueAccessTokenActionsExecuted()) {
            lifetimeInMillis = tokenReqMessageContext.getValidityPeriod();
            log.debug("Access token life time is set from OAuthTokenReqMessageContext. Token Lifetime : " +
                    lifetimeInMillis + "ms.");

            return lifetimeInMillis;
        }

        boolean isUserAccessTokenType =
                isUserAccessTokenType(tokenReqMessageContext.getOauth2AccessTokenReqDTO().getGrantType(),
                        tokenReqMessageContext);

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
     * Populate custom claims (For implicit grant).
     *
     * @param jwtClaimsSetBuilder
     * @param tokenReqMessageContext
     * @throws IdentityOAuth2Exception
     */
    protected JWTClaimsSet handleCustomClaims(JWTClaimsSet.Builder jwtClaimsSetBuilder,
                                              OAuthTokenReqMessageContext tokenReqMessageContext)
            throws IdentityOAuth2Exception {

        if (tokenReqMessageContext != null && tokenReqMessageContext.isPreIssueAccessTokenActionsExecuted()) {
            return handleCustomClaimsInPreIssueAccessTokenResponse(jwtClaimsSetBuilder, tokenReqMessageContext);
        }

        if (tokenReqMessageContext != null &&
                tokenReqMessageContext.getOauth2AccessTokenReqDTO() != null &&
                StringUtils.equals(tokenReqMessageContext.getOauth2AccessTokenReqDTO().getGrantType(),
                        OAuthConstants.GrantTypes.CLIENT_CREDENTIALS) &&
                OAuthServerConfiguration.getInstance().isSkipOIDCClaimsForClientCredentialGrant()) {

            // CC grant doesn't involve a user and hence skipping OIDC claims to CC grant type Access token.
            return jwtClaimsSetBuilder.build();
        }
        CustomClaimsCallbackHandler claimsCallBackHandler =
                OAuthServerConfiguration.getInstance().getOpenIDConnectCustomClaimsCallbackHandler();
        return claimsCallBackHandler.handleCustomClaims(jwtClaimsSetBuilder, tokenReqMessageContext);
    }

    private JWTClaimsSet handleCustomClaims(JWTClaimsSet.Builder jwtClaimsSetBuilder,
                                              OAuthTokenReqMessageContext tokenReqMessageContext, OAuthAppDO oAuthAppDO)
            throws IdentityOAuth2Exception {

        if (tokenReqMessageContext != null && tokenReqMessageContext.isPreIssueAccessTokenActionsExecuted()) {
            return handleCustomClaimsInPreIssueAccessTokenResponse(jwtClaimsSetBuilder, tokenReqMessageContext);
        }

        if (tokenReqMessageContext != null && tokenReqMessageContext.getOauth2AccessTokenReqDTO() != null &&
                shouldSkipOIDCClaimHandling(tokenReqMessageContext)) {
            /*
            CC grant and organization switch done from CC grant based token doesn't involve a user and hence skipping
            OIDC claims those cases.
             */
            return jwtClaimsSetBuilder.build();
        }

        CustomClaimsCallbackHandler claimsCallBackHandler = ClaimHandlerUtil.getClaimsCallbackHandler(oAuthAppDO);
        return claimsCallBackHandler.handleCustomClaims(jwtClaimsSetBuilder, tokenReqMessageContext);
    }

    private boolean shouldSkipOIDCClaimHandling(OAuthTokenReqMessageContext tokenReqMessageContext) {

        String grantType = tokenReqMessageContext.getOauth2AccessTokenReqDTO().getGrantType();
        // Check if the grant type is CLIENT_CREDENTIALS and the config to skip OIDC claims is enabled.
        boolean isSkipOIDCClaimsForClientCredentialGrant =
                OAuthConstants.GrantTypes.CLIENT_CREDENTIALS.equals(grantType) &&
                        OAuthServerConfiguration.getInstance().isSkipOIDCClaimsForClientCredentialGrant();
        // Check if the grant type is ORGANIZATION_SWITCH and the user type is APPLICATION
        boolean isOrgSwitchWithAppUser = OAuthConstants.GrantTypes.ORGANIZATION_SWITCH.equals(grantType) &&
                OAuthConstants.UserType.APPLICATION.equals(getAuthorizedUserType(null, tokenReqMessageContext));

        return isSkipOIDCClaimsForClientCredentialGrant || isOrgSwitchWithAppUser;
    }

    private JWTClaimsSet handleCustomClaimsInPreIssueAccessTokenResponse(JWTClaimsSet.Builder jwtClaimsSetBuilder,
                                                                         OAuthTokenReqMessageContext
                                                                                 tokenReqMessageContext) {

        Map<String, Object> customClaims = tokenReqMessageContext.getAdditionalAccessTokenClaims();

        if (customClaims != null) {
            if (log.isDebugEnabled()) {
                log.debug("Pre issue access token actions are executed. " +
                        "Returning the customized claim set from actions. Claims: " + customClaims.keySet());
            }

            customClaims.forEach(jwtClaimsSetBuilder::claim);
        }

        return jwtClaimsSetBuilder.build();
    }

    /**
     * Populate custom claims.
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

    private JWTClaimsSet handleCustomClaims(JWTClaimsSet.Builder jwtClaimsSetBuilder,
                                            OAuthAuthzReqMessageContext authzReqMessageContext, OAuthAppDO oAuthAppDO)
            throws IdentityOAuth2Exception {

        CustomClaimsCallbackHandler claimsCallBackHandler = ClaimHandlerUtil.getClaimsCallbackHandler(oAuthAppDO);
        return claimsCallBackHandler.handleCustomClaims(jwtClaimsSetBuilder, authzReqMessageContext);
    }

    private boolean isUserAccessTokenType(String grantType, OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception {
        AuthorizationGrantHandler grantHandler =
                OAuthServerConfiguration.getInstance().getSupportedGrantTypes().get(grantType);
        // If grant handler is null ideally we would not come to this point as the flow will be broken before. So we
        // can guarantee grantHandler will not be null
        return grantHandler.isOfTypeApplicationUser(tokReqMsgCtx);
    }

    private JWTClaimsSet handleTokenBinding(JWTClaimsSet.Builder jwtClaimsSetBuilder,
                                            OAuthTokenReqMessageContext tokReqMsgCtx) {

        /**
         * If OAuth.JWT.RenewTokenWithoutRevokingExisting is enabled from configurations, and current token
         * binding is null,then we will add a new token binding (request binding) to the token binding with
         * a value of a random UUID.
         * The purpose of this new token binding type is to add a random value to the token binding so that
         * "User, Application, Scope, Binding" combination will be unique for each token.
         * Previously, if a token issue request come for the same combination of "User, Application, Scope, Binding",
         * the existing JWT token will be revoked and issue a new token. but with this way, we can issue new tokens
         * without revoking the old ones.
         *
         * Add following configuration to deployment.toml file to enable this feature.
         *     [oauth.jwt.renew_token_without_revoking_existing]
         *     enable = true
         *
         * By default, the allowed grant type for this feature is "client_credentials". If you need to enable for
         * other grant types, add the following configuration to deployment.toml file.
         *     [oauth.jwt.renew_token_without_revoking_existing]
         *     enable = true
         *     allowed_grant_types = ["client_credentials","password", ...]
         */
        boolean renewWithoutRevokingExistingEnabled = Boolean.parseBoolean(IdentityUtil.
                getProperty(RENEW_TOKEN_WITHOUT_REVOKING_EXISTING_ENABLE_CONFIG));

        if (renewWithoutRevokingExistingEnabled && tokReqMsgCtx != null && tokReqMsgCtx.getTokenBinding() == null) {
            if (OAuth2ServiceComponentHolder.getJwtRenewWithoutRevokeAllowedGrantTypes()
                    .contains(tokReqMsgCtx.getOauth2AccessTokenReqDTO().getGrantType())) {
                String tokenBindingValue = UUID.randomUUID().toString();
                tokReqMsgCtx.setTokenBinding(
                        new TokenBinding(REQUEST_BINDING_TYPE, OAuth2Util.getTokenBindingReference(tokenBindingValue),
                                tokenBindingValue));
            }
        }

        if (tokReqMsgCtx != null && tokReqMsgCtx.getTokenBinding() != null) {
            // Include token binding into the jwt token.
            String bindingType = tokReqMsgCtx.getTokenBinding().getBindingType();
            jwtClaimsSetBuilder.claim(TOKEN_BINDING_REF, tokReqMsgCtx.getTokenBinding().getBindingReference());
            jwtClaimsSetBuilder.claim(TOKEN_BINDING_TYPE, bindingType);
            if (OAuth2Constants.TokenBinderType.CERTIFICATE_BASED_TOKEN_BINDER.equals(bindingType)) {
                String cnf = tokReqMsgCtx.getTokenBinding().getBindingValue();
                if (StringUtils.isNotBlank(cnf)) {
                    jwtClaimsSetBuilder.claim(OAuthConstants.CNF, Collections.singletonMap(OAuthConstants.X5T_S256,
                            tokReqMsgCtx.getTokenBinding().getBindingValue()));
                }
            }
        }
        return jwtClaimsSetBuilder.build();
    }

    /**
     * Set tenant domain of user to the JWT token's realm claim if signed with user tenant.
     * @param tenantDomain
     * @param jwtClaimsSet
     * @return
     */
    private JWTClaimsSet setSignerRealm(String tenantDomain, JWTClaimsSet jwtClaimsSet) {

        Map<String, String> realm = new HashMap<>();
        if (!OAuthServerConfiguration.getInstance().getUseSPTenantDomainValue()) {
            realm.put(OAuthConstants.OIDCClaims.SIGNING_TENANT, tenantDomain);
        }
        if (realm.size() > 0) {
            if (log.isDebugEnabled()) {
                log.debug("Setting authorized user tenant domain : " + tenantDomain +
                        " used for signing the token to the 'realm' claim of jwt token");
            }
            JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder(jwtClaimsSet);
            jwtClaimsSetBuilder.claim(OAuthConstants.OIDCClaims.REALM, realm);
            jwtClaimsSet = jwtClaimsSetBuilder.build();
        }
        return jwtClaimsSet;
    }

    /**
     * Set entity_id claim to the JWT if token persistence is disabled. This is to identify the principal subject of the
     * issuing token.
     *
     * @param jwtClaimsSetBuilder        JWT Claim Set Builder
     * @param authAuthzReqMessageContext OAuthAuthzReqMessageContext
     * @param tokenReqMessageContext     OAuthTokenReqMessageContext
     * @param authenticatedUser          Authenticated User
     * @param oAuthAppDO                 OAuthAppDO
     * @throws IdentityOAuth2Exception If an error occurs while setting entity_id claim.
     */
    protected void setClaimsForNonPersistence(JWTClaimsSet.Builder jwtClaimsSetBuilder,
                                              OAuthAuthzReqMessageContext authAuthzReqMessageContext,
                                              OAuthTokenReqMessageContext tokenReqMessageContext,
                                              AuthenticatedUser authenticatedUser,
                                              OAuthAppDO oAuthAppDO) throws IdentityOAuth2Exception {

        if (!OAuth2Util.isTokenPersistenceEnabled()) {
            try {
                /*
                 * The entity_id is used to identify the principal subject for the issuing token. For user access
                 * tokens, this is the user's unique ID. For application access tokens, this is the application's
                 * consumer key.
                 */
                String userType = getAuthorizedUserType(authAuthzReqMessageContext, tokenReqMessageContext);
                if (OAuthConstants.UserType.APPLICATION_USER.equals(userType)) {
                    jwtClaimsSetBuilder.claim(OAuth2Constants.ENTITY_ID, authenticatedUser.getUserId());
                } else if (OAuthConstants.UserType.APPLICATION.equals(userType)) {
                    jwtClaimsSetBuilder.claim(OAuth2Constants.ENTITY_ID, oAuthAppDO.getOauthConsumerKey());
                } else {
                    throw new IdentityOAuth2Exception("Invalid user type: " + userType);
                }
            } catch (UserIdNotFoundException e) {
                throw new IdentityOAuth2Exception("User id not found for user: "
                        + authenticatedUser.getLoggableMaskedUserId(), e);
            }
            if (OAuth2ServiceComponentHolder.isConsentedTokenColumnEnabled()) {
                boolean isConsented;
                if (tokenReqMessageContext != null) {
                    isConsented = tokenReqMessageContext.isConsentedToken();
                } else {
                    isConsented = authAuthzReqMessageContext.isConsentedToken();
                }
                // when no persistence of tokens, there is no existing token to check the consented value for.
                jwtClaimsSetBuilder.claim(OAuth2Constants.IS_CONSENTED, isConsented);
            }
            jwtClaimsSetBuilder.claim(OAuth2Constants.IS_FEDERATED, authenticatedUser.isFederatedUser());
        }
    }
}
