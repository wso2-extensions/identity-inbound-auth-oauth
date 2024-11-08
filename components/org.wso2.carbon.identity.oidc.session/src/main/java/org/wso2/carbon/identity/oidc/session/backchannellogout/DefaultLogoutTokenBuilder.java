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
package org.wso2.carbon.identity.oidc.session.backchannellogout;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import net.minidev.json.JSONObject;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oidc.session.OIDCSessionConstants;
import org.wso2.carbon.identity.oidc.session.OIDCSessionState;
import org.wso2.carbon.identity.oidc.session.util.OIDCSessionManagementUtil;
import org.wso2.carbon.utils.security.KeystoreUtils;

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

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;


import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth20Endpoints.OAUTH2_TOKEN_EP_URL;
import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.getResidentIdpEntityId;

/**
 * This is the logout token generator for the OpenID Connect back-channel logout Implementation. This
 * Logout token Generator utilizes the Nimbus SDK to build the Logout token.
 */
public class DefaultLogoutTokenBuilder implements LogoutTokenBuilder {

    private static final Log LOG = LogFactory.getLog(DefaultLogoutTokenBuilder.class);
    private OAuthServerConfiguration config = null;
    private JWSAlgorithm signatureAlgorithm = null;
    private static final String OPENID_IDP_ENTITY_ID = "IdPEntityId";
    private static final String ERROR_GET_RESIDENT_IDP =
            "Error while getting Resident Identity Provider of '%s' tenant.";
    private static final String BACKCHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout";

    public DefaultLogoutTokenBuilder() throws IdentityOAuth2Exception {

        config = OAuthServerConfiguration.getInstance();
        signatureAlgorithm = OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm(config.getIdTokenSignatureAlgorithm());
    }

    @Override
    @Deprecated
    public Map<String, String> buildLogoutToken(HttpServletRequest request)
            throws IdentityOAuth2Exception, InvalidOAuthClientException {

        Map<String, String> logoutTokenList = new HashMap<>();
        // Send logout token to all RPs.
        Cookie opbsCookie = OIDCSessionManagementUtil.getOPBrowserStateCookie(request);
        // For backward compatibility, SUPER_TENANT_DOMAIN was added as the cache maintained tenant.
        OIDCSessionState sessionState = getSessionState(opbsCookie != null ? opbsCookie.getValue() : null,
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        if (sessionState != null) {
            Set<String> sessionParticipants = getSessionParticipants(sessionState);
            if (!sessionParticipants.isEmpty()) {
                for (String clientID : sessionParticipants) {
                    OAuthAppDO oAuthAppDO;
                    try {
                        oAuthAppDO = getOAuthAppDO(clientID);
                    } catch (InvalidOAuthClientException e) {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("The application with client id: " + clientID
                                    + " does not exists. This application may be deleted after"
                                    + " this session is created. So skipping it in logout token list.", e);
                        }
                        continue;
                    }
                    String tenantDomain = oAuthAppDO.getAppOwner().getTenantDomain();
                    if (StringUtils.equals(clientID, getClientId(request, tenantDomain))) {
                        // No need to send logout token if the client id of the RP initiated logout is known.
                        continue;
                    }
                    addToLogoutTokenList(logoutTokenList, sessionState, clientID);
                }
            }
        }
        return logoutTokenList;
    }

    @Override
    public Map<String, String> buildLogoutToken(String opbscookie) throws IdentityOAuth2Exception,
            InvalidOAuthClientException {

        // For backward compatibility, SUPER_TENANT_DOMAIN was added as the cache maintained tenant.
        return buildLogoutToken(opbscookie, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
    }

    @Override
    public Map<String, String> buildLogoutToken(String opbscookie, String tenantDomain) throws IdentityOAuth2Exception,
            InvalidOAuthClientException {

        Map<String, String> logoutTokenList = new HashMap<>();
        // Send logout token to all RPs.
        OIDCSessionState sessionState = getSessionState(opbscookie, tenantDomain);
        if (sessionState != null) {
            Set<String> sessionParticipants = getSessionParticipants(sessionState);
            if (!sessionParticipants.isEmpty()) {
                for (String clientID : sessionParticipants) {
                    addToLogoutTokenList(logoutTokenList, sessionState, clientID);
                }
            }
        }
        return logoutTokenList;
    }

    private void addToLogoutTokenList(Map<String, String> logoutTokenList,
                                      OIDCSessionState sessionState, String clientID) throws IdentityOAuth2Exception {

        OAuthAppDO oAuthAppDO;
        try {
            oAuthAppDO = getOAuthAppDO(clientID);
        } catch (InvalidOAuthClientException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("The application with client id: " + clientID
                        + " does not exists. This application may be deleted after"
                        + " this session is created. So skipping it in logout token list.", e);
            }
            return;
        }
        String backChannelLogoutUrl = oAuthAppDO.getBackChannelLogoutUrl();
        if (StringUtils.isNotBlank(backChannelLogoutUrl)) {
            // Send back-channel logout request to all RPs those registered their back-channel logout uri.
            JWTClaimsSet jwtClaimsSet = buildJwtToken(sessionState, getTenanatDomain(oAuthAppDO), clientID);
            String logoutToken = OAuth2Util.signJWT(jwtClaimsSet, signatureAlgorithm,
                    getSigningTenantDomain(oAuthAppDO)).serialize();
            logoutTokenList.put(logoutToken, backChannelLogoutUrl);

            if (LOG.isDebugEnabled()) {
                LOG.debug("Logout token created for the client: " + clientID);
            }
        }
    }

    /**
     * Builds jwtClaimSet.
     *
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
        JSONObject event = new JSONObject().appendField(BACKCHANNEL_LOGOUT_EVENT,
                new JSONObject());

        JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
        jwtClaimsSetBuilder.subject(sub);
        jwtClaimsSetBuilder.issuer(iss);
        jwtClaimsSetBuilder.audience(audience);
        jwtClaimsSetBuilder.claim("jti", jti);
        jwtClaimsSetBuilder.claim("events", event);
        jwtClaimsSetBuilder.expirationTime(new Date(currentTimeInMillis + logoutTokenValidityInMillis));
        jwtClaimsSetBuilder.claim("iat", iat);
        jwtClaimsSetBuilder.claim("sid", sid);

        return jwtClaimsSetBuilder.build();
    }

    /**
     * Returns client id from servlet request.
     *
     * @param request      Http Servlet Request.
     * @param tenantDomain Tenant domain.
     * @return Client ID.
     * @throws IdentityOAuth2Exception     Error in validating ID token hint.
     * @throws InvalidOAuthClientException Error in validating ID token hint.
     */
    private String getClientId(HttpServletRequest request, String tenantDomain)
            throws IdentityOAuth2Exception, InvalidOAuthClientException {

        String clientId = null;
        String idToken = getIdToken(request);
        if (idToken != null) {
            if (OIDCSessionManagementUtil.isIDTokenEncrypted(idToken)) {
                try {
                    JWT decryptedIDToken = OIDCSessionManagementUtil.decryptWithRSA(tenantDomain, idToken);
                    clientId = OIDCSessionManagementUtil.extractClientIDFromDecryptedIDToken(decryptedIDToken);
                } catch (ParseException e) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Error in extracting the client ID from the ID token : " + idToken);
                    }
                }
                return clientId;
            }
            clientId = getClientIdFromIDTokenHint(idToken);
        } else {
            LOG.debug("IdTokenHint is not found in the request ");
            return null;
        }
        if (validateIdTokenHint(clientId, idToken)) {
            return clientId;
        } else {
            LOG.debug("Id Token is not valid");
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
     * Returns the OIDCsessionState of the obps cookie.
     *
     * @param opbscookie OpbsCookie.
     * @return OIDCSessionState
     */
    private OIDCSessionState getSessionState(String opbscookie, String tenantDomain) {

        if (StringUtils.isNotEmpty(opbscookie)) {
            OIDCSessionState sessionState =
                    OIDCSessionManagementUtil.getSessionManager().getOIDCSessionState(opbscookie, tenantDomain);
            return sessionState;
        }
        return null;
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

    /**
     * Returning issuer of the tenant domain.
     *
     * @param tenantDomain
     * @return issuer
     * @throws IdentityOAuth2Exception
     */
    private String getIssuer(String tenantDomain) throws IdentityOAuth2Exception {

        return getIdTokenIssuer(tenantDomain);
    }

    private String getIdTokenIssuer(String tenantDomain) throws IdentityOAuth2Exception {

        if (IdentityTenantUtil.isTenantQualifiedUrlsEnabled()) {
            try {
                // Set the correct tenant domain before creating the path.
                return ServiceURLBuilder.create().setTenant(tenantDomain).addPath(OAUTH2_TOKEN_EP_URL).build().
                        getAbsolutePublicURL();
            } catch (URLBuilderException e) {
                String errorMsg = String.format("Error while building the absolute url of the context: '%s',  for the"
                        + " tenant domain: '%s'", OAUTH2_TOKEN_EP_URL, tenantDomain);
                throw new IdentityOAuth2Exception(errorMsg, e);
            }
        } else {
            return getResidentIdpEntityId(tenantDomain);
        }
    }

    /**
     * Returns OAuthAppDo using clientID.
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
     * Returns a list of audience.
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
     * Returns ID Token.
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
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Error while decoding the ID Token Hint: " + idTokenHint, e);
                }
            }
        }
        return clientId;
    }

    /**
     * Extract client Id from ID Token Hint.
     *
     * @param idToken
     * @return
     * @throws ParseException
     */
    private String extractClientFromIdToken(String idToken) throws ParseException {

        return SignedJWT.parse(idToken).getJWTClaimsSet().getAudience().get(0);
    }

    /**
     * Validate Id Token Hint.
     *
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
                String fileName = KeystoreUtils.getKeyStoreFileLocation(tenantDomain);
                publicKey = (RSAPublicKey) keyStoreManager.getKeyStore(fileName).getCertificate(tenantDomain)
                        .getPublicKey();
            } else {
                publicKey = (RSAPublicKey) keyStoreManager.getDefaultPublicKey();
            }
            SignedJWT signedJWT = SignedJWT.parse(idToken);
            JWSVerifier verifier = new RSASSAVerifier(publicKey);

            return signedJWT.verify(verifier);
        } catch (JOSEException | ParseException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Error occurred while validating id token signature.", e);
            }
            return false;
        } catch (Exception e) {
            LOG.error("Error occurred while validating id token signature.", e);
            return false;
        }
    }

}
