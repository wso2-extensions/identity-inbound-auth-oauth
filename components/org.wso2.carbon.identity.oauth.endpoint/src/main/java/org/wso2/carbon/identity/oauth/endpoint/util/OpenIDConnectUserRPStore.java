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
import org.wso2.carbon.identity.oauth.dao.OAuthAppDAO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;

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
        repDO.setUserName(user.getAuthenticatedSubjectIdentifier());
        repDO.setTrustedAlways(trustedAlways);
        int tenantId = -1;
        if (user.getUserName() != null) {
            tenantId = IdentityTenantUtil.getTenantId(user.getTenantDomain());
        } else {
            OAuthAppDAO oAuthAppDAO = new OAuthAppDAO();
            OAuthAppDO appDO;
            try {
                appDO = oAuthAppDAO.getAppInformation(clientId);
                tenantId = IdentityTenantUtil.getTenantId(appDO.getUser().getTenantDomain());
            } catch (IdentityOAuth2Exception | InvalidOAuthClientException e) {
                throw new OAuthSystemException("Error while retrieving app");
            }
        }

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
        OpenIDUserRPDO rpDO;
        int tenantId;
        if (user.getUserName() != null) {
            tenantId = IdentityTenantUtil.getTenantId(user.getTenantDomain());
        } else {
            OAuthAppDAO oAuthAppDAO = new OAuthAppDAO();
            OAuthAppDO appDO;
            try {
                appDO = oAuthAppDAO.getAppInformation(clientId);
                tenantId = IdentityTenantUtil.getTenantId(appDO.getUser().getTenantDomain());
            } catch (IdentityOAuth2Exception | InvalidOAuthClientException e) {
                throw new OAuthSystemException("Error while retrieving app");
            }
        }

        rpDO = dao.getOpenIDUserRP(user.getAuthenticatedSubjectIdentifier(), appName, tenantId);
        if (rpDO != null && rpDO.isTrustedAlways()) {
            return true;
        }

        return false;
    }
}
