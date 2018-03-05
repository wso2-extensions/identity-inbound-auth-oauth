/*
 * Copyright (c) 2013, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.carbon.identity.oauth.endpoint.util;

import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.dao.OpenIDUserRPDAO;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.core.model.OpenIDUserRPDO;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

/**
 * Stores user consent on applications
 */
public class OpenIDConnectUserRPStore {

    private static final String DEFAULT_PROFILE_NAME = "default";
    private static OpenIDConnectUserRPStore store = new OpenIDConnectUserRPStore();

    private OpenIDConnectUserRPStore() {

    }

    public static OpenIDConnectUserRPStore getInstance() {
        return store;
    }

    /**
     * @param user
     * @param appName
     * @throws OAuthSystemException
     */
    public void putUserRPToStore(AuthenticatedUser user, String appName, boolean trustedAlways, String clientId) throws
            OAuthSystemException {
        OpenIDUserRPDO repDO = new OpenIDUserRPDO();
        repDO.setDefaultProfileName(DEFAULT_PROFILE_NAME);
        repDO.setRpUrl(appName);
        repDO.setUserName(getAuthenticatedSubjectIdentifier(user));
        repDO.setTrustedAlways(trustedAlways);

        OAuthAppDO oAuthAppDO = getOAuthApp(clientId);
        int tenantId = getTenantId(user, oAuthAppDO);

        OpenIDUserRPDAO dao = new OpenIDUserRPDAO();
        dao.createOrUpdate(repDO, tenantId);
    }

    /**
     * @param user
     * @param appName
     * @return
     * @throws OAuthSystemException
     */
    public boolean hasUserApproved(AuthenticatedUser user, String appName, String clientId) throws
            OAuthSystemException {

        OpenIDUserRPDAO dao = new OpenIDUserRPDAO();

        OAuthAppDO oAuthAppDO = getOAuthApp(clientId);
        int tenantId = getTenantId(user, oAuthAppDO);

        OpenIDUserRPDO rpDO = dao.getOpenIDUserRP(getAuthenticatedSubjectIdentifier(user), appName, tenantId);
        return rpDO != null && rpDO.isTrustedAlways();
    }

    /**
     * @param user
     * @throws OAuthSystemException
     */
    public void removeConsentForUser(AuthenticatedUser user,
                                     String clientId) throws OAuthSystemException {

        OAuthAppDO oAuthAppDO = getOAuthApp(clientId);
        int tenantId = getTenantId(user, oAuthAppDO);
        String appName = oAuthAppDO.getApplicationName();

        OpenIDUserRPDAO dao = new OpenIDUserRPDAO();
        OpenIDUserRPDO consent = dao.getOpenIDUserRP(getAuthenticatedSubjectIdentifier(user), appName, tenantId);
        if (consent != null) {
            dao.delete(consent, tenantId);
        }
    }

    private String getAuthenticatedSubjectIdentifier(AuthenticatedUser user) {

        return user.getAuthenticatedSubjectIdentifier();
    }

    private int getTenantId(AuthenticatedUser user, OAuthAppDO oauthApp) throws OAuthSystemException {

        int tenantId;
        if (user.getUserName() != null) {
            tenantId = IdentityTenantUtil.getTenantId(user.getTenantDomain());
        } else {
            tenantId = IdentityTenantUtil.getTenantId(OAuth2Util.getTenantDomainOfOauthApp(oauthApp));
        }
        return tenantId;
    }

    private OAuthAppDO getOAuthApp(String clientId) throws OAuthSystemException {

        String errorMsg = "Unable to retrieve app information for clientId: " + clientId;
        try {
            OAuthAppDO oAuthApp = OAuth2Util.getAppInformationByClientId(clientId);
            if (oAuthApp == null) {
                throw new OAuthSystemException(errorMsg);
            } else {
                return oAuthApp;
            }
        } catch (IdentityOAuth2Exception | InvalidOAuthClientException e) {
            throw new OAuthSystemException(errorMsg, e);
        }
    }

}
