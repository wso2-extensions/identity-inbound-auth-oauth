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

package org.wso2.carbon.identity.oauth.cache;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.cache.AuthenticationBaseCache;
import org.wso2.carbon.identity.core.cache.AbstractCacheListener;
import org.wso2.carbon.identity.oauth.listener.OAuthCacheRemoveListener;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.utils.CarbonUtils;

import java.util.ArrayList;
import java.util.List;

/**
 * OAuth cache.
 */
public class OAuthCache extends AuthenticationBaseCache<OAuthCacheKey, CacheEntry> {

    private static final String OAUTH_CACHE_NAME = "OAuthCache";
    private static final List<AbstractCacheListener<OAuthCacheKey, CacheEntry>> cacheListeners = new ArrayList<>();
    private static volatile OAuthCache instance;
    private static final Log LOG = LogFactory.getLog(OAuthCache.class);

    static {
        cacheListeners.add(new OAuthCacheRemoveListener());
    }

    private OAuthCache() {
        super(OAUTH_CACHE_NAME, cacheListeners);
    }

    public static OAuthCache getInstance() {
        CarbonUtils.checkSecurity();
        if (instance == null) {
            synchronized (OAuthCache.class) {
                if (instance == null) {
                    instance = new OAuthCache();
                }
            }
        }
        return instance;
    }

    @Override
    public void addToCache(OAuthCacheKey key, CacheEntry entry) {

        if (entry instanceof AccessTokenDO) {
            AccessTokenDO tokenDO = (AccessTokenDO) entry;
            String tenantDomain = tokenDO.getAuthzUser().getTenantDomain();
            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format("AccessTokenDO was added for the given token identifier: %s in the tenant: %s.",
                        ((AccessTokenDO) entry).getTokenId(), tenantDomain));
            }
            super.addToCache(key, entry, tenantDomain);
        } else {
            super.addToCache(key, entry);
        }
    }

    @Override
    public void clearCacheEntry(OAuthCacheKey key, String tenantDomain) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Hit OAuthCache for clearing in tenant domain: " + tenantDomain);
        }
        if (getValueFromCache(key, tenantDomain) == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format("No cache entry found for the given cache key in the tenant: %s.",
                        tenantDomain));
            }
            return;
        }
        if (StringUtils.isNotBlank(tenantDomain)) {
            super.clearCacheEntry(key, tenantDomain);
        } else {
            super.clearCacheEntry(key);
        }
        // Added below logs to make sure the cache is cleared properly.
        if (LOG.isDebugEnabled() && super.getValueFromCache(key, tenantDomain) == null) {
            LOG.debug("Successfully cleared OAuthCache for the provided key in tenant domain: " + tenantDomain);
        }
    }


    @Override
    public CacheEntry getValueFromCache(OAuthCacheKey key, String tenantDomain) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Hit OAuthCache for getting the cache entry in tenant domain: " + tenantDomain);
        }
        CacheEntry cacheEntry;
        if (StringUtils.isNotBlank(tenantDomain)) {
            cacheEntry = super.getValueFromCache(key, tenantDomain);
        } else {
            cacheEntry = super.getValueFromCache(key);
        }
        if (LOG.isDebugEnabled() && cacheEntry != null) {
            LOG.debug("Successfully retrieved cache entry from OauthCache for tenant domain: " + tenantDomain);
        }
        return cacheEntry;
    }
}
