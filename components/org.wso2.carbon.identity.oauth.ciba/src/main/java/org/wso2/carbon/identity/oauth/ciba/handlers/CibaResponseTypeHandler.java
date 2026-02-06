/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth.ciba.handlers;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.client.utils.URIBuilder;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.ciba.common.AuthReqStatus;
import org.wso2.carbon.identity.oauth.ciba.common.CibaConstants;
import org.wso2.carbon.identity.oauth.ciba.dao.CibaDAOFactory;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.dto.OAuthErrorDTO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.authz.handlers.AbstractResponseTypeHandler;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;

import java.net.URISyntaxException;

import static org.wso2.carbon.identity.oauth.ciba.common.CibaConstants.CIBA_SUCCESS_ENDPOINT_PATH;

/**
 * Handles authorize requests with CibaAuthCode as response type.
 */
public class CibaResponseTypeHandler extends AbstractResponseTypeHandler {

    private static Log log = LogFactory.getLog(CibaResponseTypeHandler.class);

    @Override
    public OAuth2AuthorizeRespDTO issue(OAuthAuthzReqMessageContext oauthAuthzMsgCtx) throws IdentityOAuth2Exception {

        OAuth2AuthorizeRespDTO respDTO = new OAuth2AuthorizeRespDTO();
        OAuth2AuthorizeReqDTO authorizationReqDTO = oauthAuthzMsgCtx.getAuthorizationReqDTO();
        String authRequestId = authorizationReqDTO.getNonce();
        boolean isAuthRequestProcessedSuccessfully = false;
        String authCodeKey = null;
        try {
            // Assigning authenticated user for the request that to be persisted.
            AuthenticatedUser cibaAuthenticatedUser = authorizationReqDTO.getUser();
            authCodeKey = CibaDAOFactory.getInstance().getCibaAuthMgtDAO().getCibaAuthCodeKey(authRequestId);
            String authenticatedUserId = cibaAuthenticatedUser.getUserId();

            // Get the resolved user and check if the resolved user is the same as the authenticated user.
            boolean isValidUser = validateResolvedUser(authCodeKey, authenticatedUserId);
            if  (!isValidUser) {
                throw new IdentityOAuth2ClientException("The authenticated user: " + authenticatedUserId
                        + " is not the same as the resolved user for the auth_req_id: " + authRequestId);
            }

            // Update successful authentication.
            CibaDAOFactory.getInstance().getCibaAuthMgtDAO()
                    .persistAuthenticationSuccess(authCodeKey, cibaAuthenticatedUser);

            // Building custom CallBack URL.
            OAuthAppDO oAuthAppDO = (OAuthAppDO) oauthAuthzMsgCtx.getProperty("OAuthAppDO");
            String redirectionURI = getCibaFlowCompletionPageURI(oAuthAppDO.getApplicationName(),
                    oauthAuthzMsgCtx.getAuthorizationReqDTO().getTenantDomain());
            respDTO.setCallbackURI(redirectionURI);
            isAuthRequestProcessedSuccessfully = true;
            return respDTO;
        } catch (CibaCoreException e) {
            throw new IdentityOAuth2Exception("Error occurred in persisting authenticated user and authentication " +
                    "status for the request made by client: " + authorizationReqDTO.getConsumerKey(), e);
        } catch (UserIdNotFoundException e) {
            throw new IdentityOAuth2Exception("Unable to find the authenticated user id for auth_code_key: " +
                    authRequestId, e);
        } finally {
            if  (!isAuthRequestProcessedSuccessfully && StringUtils.isNotBlank(authCodeKey)) {
                CibaDAOFactory.getInstance().getCibaAuthMgtDAO().updateStatus(authCodeKey, AuthReqStatus.FAILED);
            }
        }
    }

    @Override
    public OAuthErrorDTO handleUserConsentDenial(OAuth2Parameters oAuth2Parameters) {

        OAuthErrorDTO oAuthErrorDTO = new OAuthErrorDTO();
        String authReqID = oAuth2Parameters.getNonce();
        String authCodeKey;
        try {
            authCodeKey = CibaDAOFactory.getInstance().getCibaAuthMgtDAO().getCibaAuthCodeKey(authReqID);

            // Update authenticationStatus when user denied the consent.
            CibaDAOFactory.getInstance().getCibaAuthMgtDAO().updateStatus(authCodeKey, AuthReqStatus.CONSENT_DENIED);

            oAuthErrorDTO.setErrorDescription("User denied the consent.");
            return oAuthErrorDTO;
        } catch (CibaCoreException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error occurred in updating the authentication_status for the auth_req_id : " + authReqID +
                        "with responseType as (ciba).");
            }
        }
        return null;
    }

    @Override
    public OAuthErrorDTO handleAuthenticationFailure(OAuth2Parameters oAuth2Parameters) {

        OAuthErrorDTO oAuthErrorDTO = new OAuthErrorDTO();
        String authReqID = oAuth2Parameters.getNonce();
        String authCodeKey = null;
        try {
            authCodeKey = CibaDAOFactory.getInstance().getCibaAuthMgtDAO().getCibaAuthCodeKey(authReqID);
            CibaDAOFactory.getInstance().getCibaAuthMgtDAO().updateStatus(authCodeKey, AuthReqStatus.FAILED);
            oAuthErrorDTO.setErrorDescription("Authentication failed.");
            return oAuthErrorDTO;
        } catch (CibaCoreException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error occurred in updating the authentication_status for the ID : " + authReqID +
                        "with responseType as (ciba). ");
            }
        }
        return null;
    }

    @Override
    public boolean isAuthorizedClient(OAuthAuthzReqMessageContext authzReqMsgCtx) throws IdentityOAuth2Exception {

        OAuth2AuthorizeReqDTO authzReqDTO = authzReqMsgCtx.getAuthorizationReqDTO();
        String consumerKey = authzReqDTO.getConsumerKey();

        OAuthAppDO oAuthAppDO = (OAuthAppDO) authzReqMsgCtx.getProperty("OAuthAppDO");
        if (StringUtils.isBlank(oAuthAppDO.getGrantTypes())) {
            if (log.isDebugEnabled()) {
                log.debug("Could not find authorized grant types for client id: " + consumerKey);
            }
            return false;
        }
        String responseType = authzReqDTO.getResponseType();
        String grantType = null;
        if (StringUtils.contains(responseType, CibaConstants.OAUTH_CIBA_RESPONSE_TYPE)) {
            grantType = CibaConstants.OAUTH_CIBA_GRANT_TYPE;
        }

        if (StringUtils.isBlank(grantType)) {
            if (log.isDebugEnabled()) {
                log.debug("Valid grant type not found for client id: " + consumerKey);
            }
            return false;
        }

        if (!oAuthAppDO.getGrantTypes().contains(grantType)) {
            if (log.isDebugEnabled()) {
                // Do not change this log format as these logs use by external applications.
                log.debug("Unsupported Grant Type: " + grantType + " for client id: " + consumerKey);
            }
            return false;
        }
        return true;
    }

    /**
     * This method is used to generate the ciba flow authentication completed page URI.
     *
     * @param appName       Service provider name.
     * @param tenantDomain  Tenant domain.
     * @return Redirection URI
     */
    private static String getCibaFlowCompletionPageURI(String appName, String tenantDomain)
            throws IdentityOAuth2Exception {

        try {
            String pageURI = ServiceURLBuilder.create().addPath(CIBA_SUCCESS_ENDPOINT_PATH).build()
                    .getAbsolutePublicURL();
            URIBuilder uriBuilder = new URIBuilder(pageURI);
            uriBuilder.addParameter(org.wso2.carbon.identity.oauth2.device.constants.Constants.APP_NAME, appName);
            if (!IdentityTenantUtil.isTenantQualifiedUrlsEnabled() && isNotSuperTenant(tenantDomain)) {
                // Append tenant domain to path when the tenant-qualified url mode is disabled.
                uriBuilder.addParameter(FrameworkUtils.TENANT_DOMAIN, tenantDomain);
            }
            return uriBuilder.build().toString();
        } catch (URISyntaxException | URLBuilderException e) {
            throw new IdentityOAuth2Exception("Error occurred when getting the ciba flow authentication completed" +
                    " page URI.", e);
        }
    }

    private static boolean isNotSuperTenant(String tenantDomain) {

        return (StringUtils.isNotBlank(tenantDomain) &&
                !MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(tenantDomain));
    }

    private boolean validateResolvedUser(String authCodeKey, String authenticatedUserId) throws CibaCoreException {

        String resolvedUserId = CibaDAOFactory.getInstance().getCibaAuthMgtDAO().getResolvedUserId(authCodeKey);
        return StringUtils.equals(resolvedUserId, authenticatedUserId);
    }
}
