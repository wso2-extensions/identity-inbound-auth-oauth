package org.wso2.carbon.identity.oidc.session;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.utils.OAuthUtils;
import org.json.JSONObject;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oidc.session.util.OIDCSessionManagementUtil;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;


import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
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
    public Map<String, String> buildLogoutToken(HttpServletRequest request, HttpServletResponse response)
            throws IdentityOAuth2Exception, InvalidOAuthClientException {

        Map<String, String> logoutTokenList = new HashMap<>();
        // Send logout token to all RPs.
        OIDCSessionState sessionState = getSessionState(request);
        if (sessionState != null) {
            Set<String> sessionParticipants = getSessionParticipants(sessionState);
            if (sessionParticipants != null) {
                for (String clientID : sessionParticipants) {
                    // Setting subject.
                    String sub = sessionState.getAuthenticatedUser();
                    String jti = UUID.randomUUID().toString();

                    OAuthAppDO oAuthAppDO = OAuth2Util.getAppInformationByClientId(clientID);
                    String tenantDomain = OAuth2Util.getTenantDomainOfOauthApp(oAuthAppDO);
                    IdentityProvider identityProvider = getResidentIdp(tenantDomain);
                    FederatedAuthenticatorConfig[] fedAuthnConfigs =
                            identityProvider.getFederatedAuthenticatorConfigs();
                    // Get OIDC authenticator
                    FederatedAuthenticatorConfig samlAuthenticatorConfig =
                            IdentityApplicationManagementUtil.getFederatedAuthenticator(fedAuthnConfigs,
                                    IdentityApplicationConstants.Authenticator.OIDC.NAME);
                    // Setting issuer.
                    String iss =
                            IdentityApplicationManagementUtil.getProperty(samlAuthenticatorConfig.getProperties(),
                                    OPENID_IDP_ENTITY_ID).getValue();

                    ArrayList<String> audience = new ArrayList<String>();
                    audience.add(clientID);
                    long lifetimeInMillis = Integer.parseInt(config.getOpenIDConnectBCLogoutTokenExpiration()) * 1000;
                    long curTimeInMillis = Calendar.getInstance().getTimeInMillis();
                    Date iat = new Date(curTimeInMillis);
                    String sid = getSidClaim(sessionState);
                    JSONObject event = new JSONObject().put("http://schemas.openidnet/event/backchannel-logout",
                            new JSONObject());

                    JWTClaimsSet jwtClaimsSet = new JWTClaimsSet();
                    jwtClaimsSet.setSubject(sub);
                    jwtClaimsSet.setIssuer(iss);
                    jwtClaimsSet.setAudience(audience);
                    jwtClaimsSet.setClaim("jti", jti);
                    jwtClaimsSet.setClaim("event", event);
                    jwtClaimsSet.setExpirationTime(new Date(curTimeInMillis + lifetimeInMillis));
                    jwtClaimsSet.setClaim("iat", iat);
                    jwtClaimsSet.setClaim("sid", sid);

                    boolean isJWTSignedWithSPKey = OAuthServerConfiguration.getInstance().isJWTSignedWithSPKey();
                    String signingTenantDomain;
                    String backChannelLogoutUrl = oAuthAppDO.getBackChannelLogoutUrl();

                    if (isJWTSignedWithSPKey) {
                        // Tenant domain of the SP
                        signingTenantDomain = OAuth2Util.getTenantDomainOfOauthApp(oAuthAppDO);
                    } else {
                        // Tenant domain of the user
                        signingTenantDomain = oAuthAppDO.getUser().getTenantDomain();
                    }
                    String logoutToken =
                            OAuth2Util.signJWT(jwtClaimsSet, signatureAlgorithm, signingTenantDomain).serialize();
                    logoutTokenList.put(logoutToken, backChannelLogoutUrl);
                }
                return logoutTokenList;
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("No session participants available");
                }
            }

        } else {
            if (log.isDebugEnabled()) {
                log.debug("OIDC Session state is not available for this browser session");
            }
        }

        return null;
    }


    /**
     * Returns the OIDCsessionState of the obps cookie
     *
     * @param request
     * @return
     */
    private OIDCSessionState getSessionState(HttpServletRequest request) {

        Cookie opbsCookie = OIDCSessionManagementUtil.getOPBrowserStateCookie(request);
        String obpsCookieValue = opbsCookie.getValue();
        OIDCSessionState sessionState = OIDCSessionManagementUtil.getSessionManager()
                .getOIDCSessionState(obpsCookieValue);
        return sessionState;
    }

    /**
     * Return client id of all the RPs belong to same session
     *
     * @param sessionState
     * @return client id of all the RPs belong to same session
     */
    private Set<String> getSessionParticipants(OIDCSessionState sessionState) {

        Set<String> sessionParticipants = sessionState.getSessionParticipants();
        return sessionParticipants;
    }

    /**
     * Returns the sid of the all the RPs belong to same session
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

}
