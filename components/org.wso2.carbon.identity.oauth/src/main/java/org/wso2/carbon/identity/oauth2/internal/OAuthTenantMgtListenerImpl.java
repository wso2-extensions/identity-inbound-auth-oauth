/*
 * Copyright (c) 2015-2024, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth2.internal;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.core.AbstractIdentityTenantMgtListener;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.OAuthUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.AuthzCodeDO;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinding;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.stratos.common.exception.StratosException;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.wso2.carbon.identity.oauth.common.OAuthConstants.TokenBindings.NONE;

/**
 * Tenant management listener for OAuth related functionality.
 */
public class OAuthTenantMgtListenerImpl extends AbstractIdentityTenantMgtListener {

    @Override
    public void onPreDelete(int tenantId) throws StratosException {

        clearTokenData(tenantId);
    }

    @Override
    public void onTenantDeactivation(int tenantId) throws StratosException {

        clearTokenData(tenantId);
    }

    private void clearTokenData(int tenantId) throws StratosException {

        try {
            Set<AccessTokenDO> accessTokenDOs = OAuthTokenPersistenceFactory.getInstance()
                    .getAccessTokenDAO().getAccessTokensByTenant(tenantId);
            String organizationId =
                    OAuth2ServiceComponentHolder.getInstance().getOrganizationManager().resolveOrganizationId(
                            IdentityTenantUtil.getTenantDomain(tenantId));
            Set<AccessTokenDO> accessTokensByAuthorizedOrg =
                    OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO()
                            .getAccessTokensByAuthorizedOrg(organizationId);
            accessTokenDOs.addAll(accessTokensByAuthorizedOrg);

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

                //Clear cache
                OAuthUtil.clearOAuthCache(accessTokenDO.getConsumerKey(), accessTokenDO.getAuthzUser(),
                        OAuth2Util.buildScopeString(accessTokenDO.getScope()));
                OAuthUtil.clearOAuthCache(accessTokenDO.getConsumerKey(), accessTokenDO.getAuthzUser());
                OAuthUtil.clearOAuthCache(accessTokenDO);
                TokenBinding tokenBinding = accessTokenDO.getTokenBinding();
                String tokenBindingReference = (tokenBinding != null &&
                        StringUtils.isNotBlank(tokenBinding.getBindingReference())) ?
                        tokenBinding.getBindingReference() : NONE;
                String authorizedOrgId = StringUtils.isNotEmpty(accessTokenDO.getAuthorizedOrganizationId()) ?
                        accessTokenDO.getAuthorizedOrganizationId() : OAuthConstants.AuthorizedOrganization.NONE;
                OAuthUtil.clearOAuthCache(accessTokenDO.getConsumerKey(), accessTokenDO.getAuthzUser(),
                        OAuth2Util.buildScopeString(accessTokenDO.getScope()), tokenBindingReference, authorizedOrgId);
            }
            ArrayList<String> tokensToRevoke = new ArrayList<>();
            for (Map.Entry entry : latestAccessTokens.entrySet()) {
                tokensToRevoke.add(((AccessTokenDO) entry.getValue()).getAccessToken());
            }
            OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO()
                    .revokeAccessTokens(tokensToRevoke.toArray(new String[tokensToRevoke.size()]),
                            OAuth2Util.isHashEnabled());
            List<AuthzCodeDO> latestAuthzCodes = OAuthTokenPersistenceFactory.getInstance()
                    .getAuthorizationCodeDAO().getLatestAuthorizationCodesByTenant(tenantId);
            for (AuthzCodeDO authzCodeDO : latestAuthzCodes) {
                // remove the authorization code from the cache
                OAuthUtil.clearOAuthCache(authzCodeDO.getConsumerKey() + ":" +
                        authzCodeDO.getAuthorizationCode());

            }
            OAuthTokenPersistenceFactory.getInstance().getAuthorizationCodeDAO()
                    .deactivateAuthorizationCodes(latestAuthzCodes);
        } catch (IdentityOAuth2Exception e) {
            throw new StratosException("Error occurred while revoking the access tokens in tenant " + tenantId, e);
        } catch (OrganizationManagementException e) {
            throw new StratosException(e.getMessage(), e);
        }
    }
}
