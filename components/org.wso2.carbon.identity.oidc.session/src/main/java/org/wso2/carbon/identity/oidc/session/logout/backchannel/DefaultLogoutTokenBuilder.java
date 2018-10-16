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
package org.wso2.carbon.identity.oidc.session.logout.backchannel;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONObject;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oidc.session.OIDCSessionState;
import org.wso2.carbon.identity.oidc.session.util.OIDCSessionManagementUtil;

import javax.servlet.http.HttpServletRequest;
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


    public DefaultLogoutTokenBuilder() throws IdentityOAuth2Exception {

        config = OAuthServerConfiguration.getInstance();
        signatureAlgorithm = OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm(config.getIdTokenSignatureAlgorithm());
    }

    @Override
    public Map<String, String> buildLogoutToken(HttpServletRequest request)
            throws IdentityOAuth2Exception, InvalidOAuthClientException {

        Map<String, String> logoutTokenList = new HashMap<>();
        // Send logout token to all RPs.
        OIDCSessionState sessionState = OIDCSessionManagementUtil.getSessionState(request);
        if (sessionState != null) {
            Set<String> sessionParticipants = OIDCSessionManagementUtil.getSessionParticipants(sessionState);
            if (!sessionParticipants.isEmpty()) {
                for (String clientID : sessionParticipants) {
                    OAuthAppDO oAuthAppDO = OIDCSessionManagementUtil.getOAuthAppDO(clientID);
                    String backChannelLogoutUrl = oAuthAppDO.getBackChannelLogoutUrl();

                    if (StringUtils.equals(clientID, OIDCSessionManagementUtil.getClientId(request))) {
                        // No need to send logut token if the client id of the RP initiated logout is known.
                        continue;
                    }
                    if (StringUtils.isNotBlank(backChannelLogoutUrl)) {
                        // Send back-channel logout request to all RPs those registered their back-channel logout uri.

                        JWTClaimsSet jwtClaimsSet = buildJwtToken(sessionState, OIDCSessionManagementUtil.getTenantDomain(oAuthAppDO), clientID);
                        String logoutToken =
                                OAuth2Util.signJWT(jwtClaimsSet, signatureAlgorithm, OIDCSessionManagementUtil.getSigningTenantDomain(oAuthAppDO))
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
        String iss = OIDCSessionManagementUtil.getIssuer(tenantDomain);
        List<String> audience = OIDCSessionManagementUtil.getAudience(clientID);
        long logoutTokenValidityInMillis = getLogoutTokenExpiryInMillis();
        long currentTimeInMillis = Calendar.getInstance().getTimeInMillis();
        Date iat = new Date(currentTimeInMillis);
        String sid = OIDCSessionManagementUtil.getSidClaim(sessionState);
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
     * Returns Logout Token Expiration time.
     *
     * @return
     */
    private long getLogoutTokenExpiryInMillis() {

        return Integer.parseInt(config.getOpenIDConnectBCLogoutTokenExpiration()) *
                1000L;
    }

}
