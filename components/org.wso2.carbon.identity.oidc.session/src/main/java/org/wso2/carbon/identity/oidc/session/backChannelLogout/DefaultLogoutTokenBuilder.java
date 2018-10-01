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
package org.wso2.carbon.identity.oidc.session.backChannelLogout;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONObject;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oidc.session.OIDCSessionConstants;
import org.wso2.carbon.identity.oidc.session.OIDCSessionState;
import org.wso2.carbon.identity.oidc.session.util.OIDCSessionManagementUtil;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * This is the logout token generator for the OpenID Connect back-channel logout Implementation. This
 * Logout token Generator utilizes the Nimbus SDK to build the Logout token.
 */
public class DefaultLogoutTokenBuilder implements LogoutTokenBuilder {

    public static final Log log = LogFactory.getLog(DefaultLogoutTokenBuilder.class);
    private OAuthServerConfiguration config = null;
    private JWSAlgorithm signatureAlgorithm = null;
    private static final String OPENID_IDP_ENTITY_ID = "IdPEntityId";
    private static final String ERROR_GET_RESIDENT_IDP =
            "Error while getting Resident Identity Provider of '%s' tenant.";

    public DefaultLogoutTokenBuilder() throws IdentityOAuth2Exception {

        config = OAuthServerConfiguration.getInstance();
        signatureAlgorithm = OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm(config.getIdTokenSignatureAlgorithm());
    }

    @Override
    public Map<String, String> buildLogoutToken(HttpServletRequest request)
            throws IdentityOAuth2Exception, InvalidOAuthClientException {

        Map<String, String> logoutTokenList = new HashMap<>();
        // Send logout token to all RPs.
        OIDCSessionState sessionState = getSessionState(request);
        if (sessionState != null) {
            Set<String> sessionParticipants = getSessionParticipants(sessionState);
            if (!sessionParticipants.isEmpty()) {
                for (String clientID : sessionParticipants) {
                    OAuthAppDO oAuthAppDO = getOAuthAppDO(clientID);
                    String backChannelLogoutUrl = oAuthAppDO.getBackChannelLogoutUrl();

                    if (StringUtils.equals(clientID, getClientId(request))) {
                        // No need to send logut token if the client id of the RP initiated logout is known.
                        continue;
                    }
                    if (StringUtils.isNotBlank(backChannelLogoutUrl)) {
                        // Send back-channel logout request to all RPs those registered their back-channel logout uri.

                        JWTClaimsSet jwtClaimsSet = buildJwtToken(sessionState, getTenanatDomain(oAuthAppDO), clientID);
                        String logoutToken =
                                OAuth2Util.signJWT(jwtClaimsSet, signatureAlgorithm, getSigningTenantDomain(oAuthAppDO))
                                        .serialize();
                        logoutTokenList.put(logoutToken, backChannelLogoutUrl);

                        if (log.isDebugEnabled()) {
                            log.debug("Logout token created for the client: " + clientID);
                        }
                    }
                }
            }
        }
        return logoutTokenList;
    }

    /**
     * Builds jwtClaimSet.
     * @param sessionState
     * @param tenantDomain
     * @param clientID
     * @return
     * @throws IdentityOAuth2Exception
     */
    private JWTClaimsSet buildJwtToken(OIDCSessionState sessionState, String tenantDomain, String clientID)
            throws IdentityOAuth2Exception {

        String sub = sessionState.getAuthenticatedUser();
        String jti = UUID.randomUUID().toString();
        String iss = getIssuer(tenantDomain);
        List<String> audience = getAudience(clientID);
        long logoutTokenValidityInMillis = getLogoutTokenExpiryInMillis();
        long currentTimeInMillis = Calendar.getInstance().getTimeInMillis();
        Date iat = new Date(currentTimeInMillis);
        String sid = getSidClaim(sessionState);
        JSONObject event = new JSONObject().put("http://schemas.openidnet/event/backchannel-logout",
                new JSONObject());

        JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
        jwtClaimsSetBuilder.subject(sub);
        jwtClaimsSetBuilder.issuer(iss);
        jwtClaimsSetBuilder.audience(audience);
        jwtClaimsSetBuilder.claim("jti", jti);
        jwtClaimsSetBuilder.claim("event", event);
        jwtClaimsSetBuilder.expirationTime(new Date(currentTimeInMillis + logoutTokenValidityInMillis));
        jwtClaimsSetBuilder.claim("iat", iat);
        jwtClaimsSetBuilder.claim("sid", sid);

        return jwtClaimsSetBuilder.build();
    }

    /**
     * Returns client id from servlet request.
     * @param request
     * @return
     * @throws IdentityOAuth2Exception
     * @throws InvalidOAuthClientException
     */
    private String getClientId(HttpServletRequest request)
            throws IdentityOAuth2Exception, InvalidOAuthClientException {

        String clientId;
        String idToken = getIdToken(request);
        if (idToken != null) {
            clientId = getClientIdFromIDTokenHint(idToken);
        } else {
            log.debug("IdTokenHint is not found in the request ");
            return null;
        }
        if (validateIdTokenHint(clientId, idToken)) {
            return clientId;
        } else {
            log.debug("Id Token is not valid");
            return null;
        }
    }

    /**
     * Returns signing tenant domain.
     *
     * @param oAuthAppDO
     * @return
     */
    private String getSigningTenantDomain(OAuthAppDO oAuthAppDO) {

        boolean isJWTSignedWithSPKey = OAuthServerConfiguration.getInstance().isJWTSignedWithSPKey();
        String signingTenantDomain;

        if (isJWTSignedWithSPKey) {
            // Tenant domain of the SP.
            signingTenantDomain = getTenanatDomain(oAuthAppDO);
        } else {
            // Tenant domain of the user.
            signingTenantDomain = oAuthAppDO.getUser().getTenantDomain();
        }
        return signingTenantDomain;
    }


    /**
     * Returns the OIDCsessionState of the obps cookie
     *
     * @param request
     * @return
     */
    private OIDCSessionState getSessionState(HttpServletRequest request) {

        Cookie opbsCookie = OIDCSessionManagementUtil.getOPBrowserStateCookie(request);
        if (opbsCookie !=null) {
        String obpsCookieValue = opbsCookie.getValue();
            OIDCSessionState sessionState = OIDCSessionManagementUtil.getSessionManager()
                    .getOIDCSessionState(obpsCookieValue);
            return sessionState;
        }else {
            return null;
        }
    }

    /**
     * Return client id of all the RPs belong to same session.
     *
     * @param sessionState
     * @return client id of all the RPs belong to same session
     */
    private Set<String> getSessionParticipants(OIDCSessionState sessionState) {

        Set<String> sessionParticipants = sessionState.getSessionParticipants();
        return sessionParticipants;
    }

    /**
     * Returns the sid of the all the RPs belong to same session.
     *
     * @param sessionState
     * @return
     */
    private String getSidClaim(OIDCSessionState sessionState) {

        String sidClaim = sessionState.getSidClaim();
        return sidClaim;
    }

    private IdentityProvider getResidentIdp(String tenantDomain) throws IdentityOAuth2Exception {

        try {
            return IdentityProviderManager.getInstance().getResidentIdP(tenantDomain);
        } catch (IdentityProviderManagementException e) {
            String errorMsg = String.format(ERROR_GET_RESIDENT_IDP, tenantDomain);
            throw new IdentityOAuth2Exception(errorMsg, e);
        }
    }

    /**
     * Returning issuer of the tenant domain.
     *
     * @param tenantDomain
     * @return issuer
     * @throws IdentityOAuth2Exception
     */
    private String getIssuer(String tenantDomain) throws IdentityOAuth2Exception {

        IdentityProvider identityProvider = getResidentIdp(tenantDomain);
        FederatedAuthenticatorConfig[] fedAuthnConfigs =
                identityProvider.getFederatedAuthenticatorConfigs();
        // Get OIDC authenticator.
        FederatedAuthenticatorConfig oidcAuthenticatorConfig =
                IdentityApplicationManagementUtil.getFederatedAuthenticator(fedAuthnConfigs,
                        IdentityApplicationConstants.Authenticator.OIDC.NAME);
        // Setting issuer.
        String issuer =
                IdentityApplicationManagementUtil.getProperty(oidcAuthenticatorConfig.getProperties(),
                        OPENID_IDP_ENTITY_ID).getValue();
        return issuer;
    }

    /**
     * Returns OAuthAppDo using clientID
     *
     * @param clientID
     * @return
     * @throws IdentityOAuth2Exception
     * @throws InvalidOAuthClientException
     */
    private OAuthAppDO getOAuthAppDO(String clientID) throws IdentityOAuth2Exception, InvalidOAuthClientException {

        OAuthAppDO oAuthAppDO = OAuth2Util.getAppInformationByClientId(clientID);
        return oAuthAppDO;
    }

    /**
     * Returns tenant domain.
     *
     * @param oAuthAppDO
     * @return
     */
    private String getTenanatDomain(OAuthAppDO oAuthAppDO) {

        String tenantDomain = OAuth2Util.getTenantDomainOfOauthApp(oAuthAppDO);
        return tenantDomain;
    }

    /**
     * Returns a list of audience
     *
     * @param clientID
     * @return
     */
    private List<String> getAudience(String clientID) {

        ArrayList<String> audience = new ArrayList<String>();
        audience.add(clientID);
        return audience;
    }

    /**
     * Returns Logout Token Expiration time.
     *
     * @return
     */
    private long getLogoutTokenExpiryInMillis() {

        return Integer.parseInt(config.getOpenIDConnectBCLogoutTokenExpiration()) *
                1000L;
    }

    /**
     * Returns ID Token
     *
     * @param request
     * @return
     */
    private String getIdToken(HttpServletRequest request) {

        String idTokenHint = request.getParameter(OIDCSessionConstants.OIDC_ID_TOKEN_HINT_PARAM);
        if (idTokenHint != null) {
            return idTokenHint;
        }
        return null;
    }

    /**
     * Returns client ID from ID Token Hint.
     *
     * @param idTokenHint
     * @return
     */
    private String getClientIdFromIDTokenHint(String idTokenHint) {

        String clientId = null;
        if (StringUtils.isNotBlank(idTokenHint)) {
            try {
                clientId = extractClientFromIdToken(idTokenHint);
            } catch (ParseException e) {
                log.error("Error while decoding the ID Token Hint.", e);
            }
        }
        return clientId;
    }

    /**
     * Extract client Id from ID Token Hint.
     * @param idToken
     * @return
     * @throws ParseException
     */
    private String extractClientFromIdToken(String idToken) throws ParseException {

        return SignedJWT.parse(idToken).getJWTClaimsSet().getAudience().get(0);
    }

    /**
     * Validate Id Token Hint.
     * @param clientId
     * @param idToken
     * @return
     * @throws IdentityOAuth2Exception
     * @throws InvalidOAuthClientException
     */
    private Boolean validateIdTokenHint(String clientId, String idToken) throws IdentityOAuth2Exception,
            InvalidOAuthClientException {

        String tenantDomain = getSigningTenantDomain(getOAuthAppDO(clientId));
        if (StringUtils.isEmpty(tenantDomain)) {
            return false;
        }
        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        RSAPublicKey publicKey;

        try {
            KeyStoreManager keyStoreManager = KeyStoreManager.getInstance(tenantId);

            if (!tenantDomain.equals(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME)) {
                String ksName = tenantDomain.trim().replace(".", "-");
                String jksName = ksName + ".jks";
                publicKey = (RSAPublicKey) keyStoreManager.getKeyStore(jksName).getCertificate(tenantDomain)
                        .getPublicKey();
            } else {
                publicKey = (RSAPublicKey) keyStoreManager.getDefaultPublicKey();
            }
            SignedJWT signedJWT = SignedJWT.parse(idToken);
            JWSVerifier verifier = new RSASSAVerifier(publicKey);

            return signedJWT.verify(verifier);
        } catch (JOSEException | ParseException e) {
            log.error("Error occurred while validating id token signature.", e);
            return false;
        } catch (Exception e) {
            log.error("Error occurred while validating id token signature.", e);
            return false;
        }
    }

}
