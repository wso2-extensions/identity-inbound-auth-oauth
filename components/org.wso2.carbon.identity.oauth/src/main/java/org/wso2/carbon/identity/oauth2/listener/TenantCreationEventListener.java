/*
 * Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.listener;

import org.wso2.carbon.identity.oauth.OAuthUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.AuthzCodeDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.stratos.common.beans.TenantInfoBean;
import org.wso2.carbon.stratos.common.exception.StratosException;
import org.wso2.carbon.stratos.common.listeners.TenantMgtListener;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * This is an implementation of TenantMgtListener. This uses
 * to generate OIDC scopes in registry
 */
public class TenantCreationEventListener implements TenantMgtListener {

    @Override
    public void onTenantCreate(TenantInfoBean tenantInfoBean) throws StratosException {

        int tenantId = tenantInfoBean.getTenantId();
        OAuth2Util.initiateOIDCScopes(tenantId);
        OAuth2Util.initiateOAuthScopePermissionsBindings(tenantId);
    }

    @Override
    public void onTenantUpdate(TenantInfoBean tenantInfoBean) throws StratosException {

    }

    @Override
    public void onTenantDelete(int i) {

    }

    @Override
    public void onTenantRename(int i, String s, String s1) throws StratosException {

    }

    @Override
    public void onTenantInitialActivation(int i) throws StratosException {

    }

    @Override
    public void onTenantActivation(int i) throws StratosException {

    }

    @Override
    public void onTenantDeactivation(int tenantId) throws StratosException {

        revokeTokens(tenantId);
    }

    @Override
    public void onSubscriptionPlanChange(int i, String s, String s1) throws StratosException {

    }

    @Override
    public int getListenerOrder() {

        return 0;
    }

    @Override
    public void onPreDelete(int tenantId) throws StratosException {

        revokeTokens(tenantId);
    }

    private void revokeTokens(int tenantId) throws StratosException {

        try {
            Set<AccessTokenDO> accessTokenDOs = OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO()
                    .getAccessTokensByTenant(tenantId);
            Map<String, AccessTokenDO> latestAccessTokens = new HashMap<>();

            for (AccessTokenDO accessTokenDO : accessTokenDOs) {
                String keyString = accessTokenDO.getConsumerKey() + ":" + accessTokenDO.getAuthzUser() + ":" +
                        OAuth2Util.buildScopeString(accessTokenDO.getScope()) + ":"
                        + accessTokenDO.getAuthzUser().getFederatedIdPName();
                AccessTokenDO accessTokenDOFromMap = latestAccessTokens.get(keyString);
                if (accessTokenDOFromMap != null) {
                    if (accessTokenDOFromMap.getIssuedTime().before(accessTokenDO.getIssuedTime())) {
                        latestAccessTokens.put(keyString, accessTokenDO);
                    }
                } else {
                    latestAccessTokens.put(keyString, accessTokenDO);
                }

                OAuthUtil.clearOAuthCache(accessTokenDO.getConsumerKey(), accessTokenDO.getAuthzUser(),
                        OAuth2Util.buildScopeString(accessTokenDO.getScope()));
                OAuthUtil.clearOAuthCache(accessTokenDO.getConsumerKey(), accessTokenDO.getAuthzUser());
                OAuthUtil.clearOAuthCache(accessTokenDO.getAccessToken());
            }

            OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO().revokeAccessTokens(
                    latestAccessTokens
                            .values()
                            .stream()
                            .map(AccessTokenDO::getAccessToken)
                            .toArray(String[]::new),
                    OAuth2Util.isHashEnabled());

            List<AuthzCodeDO> latestAuthzCodes = OAuthTokenPersistenceFactory.getInstance()
                    .getAuthorizationCodeDAO().getLatestAuthorizationCodesByTenant(tenantId);

            // Remove the authorization code from the cache.
            latestAuthzCodes.stream()
                    .map(authzCodeDO -> authzCodeDO.getConsumerKey() + ":" + authzCodeDO.getAuthorizationCode())
                    .forEach(OAuthUtil::clearOAuthCache);

            OAuthTokenPersistenceFactory.getInstance()
                    .getAuthorizationCodeDAO().deactivateAuthorizationCodes(latestAuthzCodes);
        } catch (IdentityOAuth2Exception e) {
            throw new StratosException("Error occurred while revoking Access Token of tenant: " + tenantId, e);
        }
    }

}
