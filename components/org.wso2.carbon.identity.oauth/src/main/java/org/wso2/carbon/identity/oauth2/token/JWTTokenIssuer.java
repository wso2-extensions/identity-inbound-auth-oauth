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
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.config.SpOAuth2ExpiryTimeConfiguration;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.CustomClaimsCallbackHandler;

import java.security.Key;
import java.security.interfaces.RSAPrivateKey;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

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

    private static final String KEY_STORE_EXTENSION = ".jks";
    private static final String AUTHORIZATION_PARTY = "azp";
    private static final String AUDIENCE = "aud";

    private static final Log log = LogFactory.getLog(JWTTokenIssuer.class);

    // We are keeping a private key map which will have private key for each tenant domain. We are keeping this as a
    // static Map since then we don't need to read the key from keystore every time.
    private static Map<Integer, Key> privateKeys = new ConcurrentHashMap<>();
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
                    oAuthTokenReqMessageContext.getAuthorizedUser().toString());
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
                    "user " + oAuthAuthzReqMessageContext.getAuthorizationReqDTO().getUser().toString());
        }

        try {
            return this.buildJWTToken(oAuthAuthzReqMessageContext);
        } catch (IdentityOAuth2Exception e) {
            throw new OAuthSystemException(e);
        }
    }

    /**
     * Build a signed jwt token from OauthToken request message context.
     *
     * @param request Token request message context.
     * @return Signed jwt string.
     * @throws IdentityOAuth2Exception
     */
    protected String buildJWTToken(OAuthTokenReqMessageContext request)
            throws IdentityOAuth2Exception {

        // Set claims to jwt token.
        JWTClaimsSet jwtClaimsSet = createJWTClaimSet(null, request, request.getOauth2AccessTokenReqDTO()
                .getClientId());

        if (Arrays.asList((request.getScope())).contains(AUDIENCE)) {
            jwtClaimsSet.setAudience(Arrays.asList(request.getScope()));
        }

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
    protected String buildJWTToken(OAuthAuthzReqMessageContext request)
            throws IdentityOAuth2Exception {

        // Set claims to jwt token.
        JWTClaimsSet jwtClaimsSet = createJWTClaimSet(request, null, request.getAuthorizationReqDTO().getConsumerKey());

        if (Arrays.asList((request.getApprovedScope())).contains(AUDIENCE)) {
            jwtClaimsSet.setAudience(Arrays.asList(request.getApprovedScope()));
        }

        if (JWSAlgorithm.NONE.getName().equals(signatureAlgorithm.getName())) {
            return new PlainJWT(jwtClaimsSet).serialize();
        }

        return signJWT(jwtClaimsSet, null, request);
    }

    /**
     * Sign ghe JWT token according to the given signature signing algorithm.
     * @param jwtClaimsSet JWT claim set to be signed.
     * @param tokenContext Token context.
     * @param authorizationContext Authorization context.
     * @return Signed JWT.
     * @throws IdentityOAuth2Exception
     */
    protected String signJWT(JWTClaimsSet jwtClaimsSet, OAuthTokenReqMessageContext tokenContext,
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
     * Sign the JWT token with RSA (SHA-256, SHA-384, SHA-512) algorithm.
     * @param jwtClaimsSet JWT claim set to be signed.
     * @param tokenContext Token context if available.
     * @param authorizationContext Authorization context if available.
     * @return Signed JWT token.
     * @throws IdentityOAuth2Exception
     */
    protected String signJWTWithRSA(JWTClaimsSet jwtClaimsSet, OAuthTokenReqMessageContext tokenContext,
                                  OAuthAuthzReqMessageContext authorizationContext) throws IdentityOAuth2Exception {

        try {
            String tenantDomain = null;

            // Read the property whether we have to get the tenant domain of the SP instead of user.
            if (OAuthServerConfiguration.getInstance().getUseSPTenantDomainValue()) {
                tenantDomain = OAuth2Util.getAppInformationByClientId(authorizationContext.getAuthorizationReqDTO()
                        .getConsumerKey()).getUser().getTenantDomain();
            } else if (tokenContext != null) {
                tenantDomain = tokenContext.getAuthorizedUser().getTenantDomain();
            } else if (authorizationContext != null) {
                tenantDomain = authorizationContext.getAuthorizationReqDTO().getUser().getTenantDomain();
            }

            if (tenantDomain == null) {
                throw new IdentityOAuth2Exception("Cannot resolve the tenant domain of the user.");
            }

            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);

            Key privateKey;
            if (privateKeys.containsKey(tenantId)) {

                // PrivateKey will not be null because containsKey() true says given key is exist and ConcurrentHashMap
                // does not allow to store null values.
                privateKey = privateKeys.get(tenantId);
            } else {

                // Get tenant's key store manager.
                KeyStoreManager tenantKSM = KeyStoreManager.getInstance(tenantId);
                if (MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(tenantDomain)) {
                    try {
                        privateKey = tenantKSM.getDefaultPrivateKey();
                    } catch (Exception e) {
                        throw new IdentityOAuth2Exception("Error while obtaining private key for super tenant", e);
                    }
                } else {

                    // Derive key store name.
                    String ksName = tenantDomain.trim().replace(".", "-");
                    String jksName = ksName + KEY_STORE_EXTENSION;

                    // Obtain private key.
                    privateKey = tenantKSM.getPrivateKey(jksName, tenantDomain);
                }

                // Add the private key to the static concurrent hash map for later uses.
                privateKeys.put(tenantId, privateKey);
            }

            JWSSigner signer = new RSASSASigner((RSAPrivateKey) privateKey);
            SignedJWT signedJWT = new SignedJWT(new JWSHeader((JWSAlgorithm) signatureAlgorithm), jwtClaimsSet);
            signedJWT.sign(signer);
            return signedJWT.serialize();
        } catch (JOSEException | InvalidOAuthClientException e) {
            throw new IdentityOAuth2Exception("Error occurred while signing JWT", e);
        }
    }

    // TODO: Implement JWT signing with HMAC SHA (SHA-256, SHA-384, SHA-512).
    protected String signJWTWithHMAC(JWTClaimsSet jwtClaimsSet, OAuthTokenReqMessageContext tokenContext,
                                   OAuthAuthzReqMessageContext authorizationContext) throws IdentityOAuth2Exception {

        throw new IdentityOAuth2Exception("Given signature algorithm " + signatureAlgorithm + " is not supported " +
                "by the current implementation.");
    }

    // TODO: Implement JWT signing with ECDSA (SHA-256, SHA-384, SHA-512).
    protected String signJWTWithECDSA(JWTClaimsSet jwtClaimsSet, OAuthTokenReqMessageContext tokenContext,
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

        throw new IdentityOAuth2Exception("Unsupported Signature Algorithm in identity.xml");
    }

    /**
     * Create a JWT claim set according to the JWT format.
     * @param authAuthzReqMessageContext Oauth authorization request message context.
     * @param tokenReqMessageContext Token request message context.
     * @param consumerKey Consumer key of the application.
     * @return JWT claim set.
     * @throws IdentityOAuth2Exception
     */
    private JWTClaimsSet createJWTClaimSet(OAuthAuthzReqMessageContext authAuthzReqMessageContext,
                                           OAuthTokenReqMessageContext tokenReqMessageContext, String consumerKey)
            throws IdentityOAuth2Exception {

        AuthenticatedUser user;
        if (authAuthzReqMessageContext != null) {
            user = authAuthzReqMessageContext.getAuthorizationReqDTO().getUser();
        } else {
            user = tokenReqMessageContext.getAuthorizedUser();
        }

        String issuer = OAuth2Util.getIDTokenIssuer();
        int tenantId = OAuth2Util.getTenantId(user.getTenantDomain());
        SpOAuth2ExpiryTimeConfiguration spTimeConfigObj = OAuth2Util.getSpTokenExpiryTimeConfig(consumerKey, tenantId);

        long lifetimeInMillis = OAuthServerConfiguration.getInstance()
                .getApplicationAccessTokenValidityPeriodInSeconds() * 1000;

        if (spTimeConfigObj.getApplicationAccessTokenExpiryTime() != null) {
            lifetimeInMillis = spTimeConfigObj.getApplicationAccessTokenExpiryTime();
        }

        long curTimeInMillis = Calendar.getInstance().getTimeInMillis();

        // Set the default claims.
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet();
        jwtClaimsSet.setIssuer(issuer);
        jwtClaimsSet.setSubject(user.getAuthenticatedSubjectIdentifier());
        jwtClaimsSet.setClaim(AUTHORIZATION_PARTY, consumerKey);
        jwtClaimsSet.setExpirationTime(new Date(curTimeInMillis + lifetimeInMillis));
        jwtClaimsSet.setIssueTime(new Date(curTimeInMillis));
        jwtClaimsSet.setJWTID(UUID.randomUUID().toString());

        // This is a spec (openid-connect-core-1_0:2.0) requirement for ID tokens. But we are keeping this in JWT
        // as well.
        jwtClaimsSet.setAudience(Collections.singletonList(consumerKey));

        CustomClaimsCallbackHandler claimsCallBackHandler =
                OAuthServerConfiguration.getInstance().getOpenIDConnectCustomClaimsCallbackHandler();

        if (authAuthzReqMessageContext != null) {
            claimsCallBackHandler.handleCustomClaims(jwtClaimsSet, authAuthzReqMessageContext);
        } else {
            claimsCallBackHandler.handleCustomClaims(jwtClaimsSet, tokenReqMessageContext);
        }

        return jwtClaimsSet;
    }
}
