/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.dao;

import org.wso2.carbon.identity.oauth2.IdentityOAuth2ScopeConsentException;
import org.wso2.carbon.identity.oauth2.internal.cache.OAuthUserConsentedScopeCache;
import org.wso2.carbon.identity.oauth2.internal.cache.OAuthUserConsentedScopeCacheEntry;
import org.wso2.carbon.identity.oauth2.model.UserApplicationScopeConsentDO;

import java.util.List;

/**
 * Cache backed OAuth user consented scopes management data access object implementation.
 */
public class CacheBackedOAuthUserConsentedScopesDAOImpl implements OAuthUserConsentedScopesDAO {

    private final OAuthUserConsentedScopeCache cache = OAuthUserConsentedScopeCache.getInstance();
    private final OAuthUserConsentedScopesDAO dao = new OAuthUserConsentedScopesDAOImpl();

    @Override
    public UserApplicationScopeConsentDO getUserConsentForApplication(String userId, String appId, int tenantId)
            throws IdentityOAuth2ScopeConsentException {

        OAuthUserConsentedScopeCacheEntry entry = cache.getValueFromCache(userId, tenantId);
        if (entry != null && entry.getAppID().equals(appId)) {
            return entry.getUserApplicationScopeConsentDO();
        }
        UserApplicationScopeConsentDO userConsent = dao.getUserConsentForApplication(userId, appId, tenantId);
        cache.addToCache(userId, new OAuthUserConsentedScopeCacheEntry(appId, userConsent), tenantId);
        return userConsent;
    }

    @Override
    public List<UserApplicationScopeConsentDO> getUserConsents(String userId, int tenantId)
            throws IdentityOAuth2ScopeConsentException {

        return dao.getUserConsents(userId, tenantId);
    }

    @Override
    public void addUserConsentForApplication(String userId, int tenantId, UserApplicationScopeConsentDO userConsent)
            throws IdentityOAuth2ScopeConsentException {

        cache.clearCacheEntry(userId, tenantId);
        dao.addUserConsentForApplication(userId, tenantId, userConsent);
    }

    @Override
    public void updateExistingConsentForApplication(String userId, String appId, int tenantId,
                                                    UserApplicationScopeConsentDO consentsToBeAdded,
                                                    UserApplicationScopeConsentDO consentsToBeUpdated)
            throws IdentityOAuth2ScopeConsentException {

        cache.clearCacheEntry(userId, tenantId);
        dao.updateExistingConsentForApplication(userId, appId, tenantId, consentsToBeAdded, consentsToBeUpdated);
    }

    @Override
    public void deleteUserConsentOfApplication(String userId, String appId, int tenantId)
            throws IdentityOAuth2ScopeConsentException {

        cache.clearCacheEntry(userId, tenantId);
        dao.deleteUserConsentOfApplication(userId, appId, tenantId);
    }

    @Override
   public void revokeConsentOfApplication(String appId, int tenantId) throws IdentityOAuth2ScopeConsentException {

        dao.revokeConsentOfApplication(appId, tenantId);
    }

    @Override
    public void deleteUserConsents(String userId, int tenantId) throws IdentityOAuth2ScopeConsentException {

        cache.clearCacheEntry(userId, tenantId);
        dao.deleteUserConsents(userId, tenantId);
    }
}
