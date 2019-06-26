/*
 * Copyright (c) 2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.store.SessionDataStore;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.cache.BaseCache;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.utils.CarbonUtils;

import java.util.concurrent.TimeUnit;

/**
 * Stores authenticated user attributes and OpenID Connect specific attributes during OIDC Authorization request
 * processing. Those values are later required to serve OIDC Token request and build IDToken.
 */
public class AuthorizationGrantCache extends BaseCache<AuthorizationGrantCacheKey, AuthorizationGrantCacheEntry> {
    private static final String AUTHORIZATION_GRANT_CACHE_NAME = "AuthorizationGrantCache";

    private static volatile AuthorizationGrantCache instance;
    private static final Log log = LogFactory.getLog(AuthorizationGrantCache.class);

    /**
     * Private constructor which will not allow to create objects of this class from outside
     */
    private AuthorizationGrantCache() {
        super(AUTHORIZATION_GRANT_CACHE_NAME);
    }

    /**
     * Singleton method
     *
     * @return AuthorizationGrantCache
     */
    public static AuthorizationGrantCache getInstance() {
        CarbonUtils.checkSecurity();
        if (instance == null) {
            synchronized (AuthorizationGrantCache.class) {
                if (instance == null) {
                    instance = new AuthorizationGrantCache();
                }
            }
        }
        return instance;
    }
    /**
     * Add a cache entry by access token.
     *
     * @param key   Key which cache entry is indexed.
     * @param entry Actual object where cache entry is placed.
     */
    public void addToCacheByToken(AuthorizationGrantCacheKey key, AuthorizationGrantCacheEntry entry) {
        super.addToCache(key, entry);
        String tokenId = entry.getTokenId();
        if (tokenId == null) {
            tokenId = replaceFromTokenId(key.getUserAttributesId());
            entry.setTokenId(tokenId);
        }
        storeToSessionStore(tokenId, entry);

    }

    /**
     * Retrieves a cache entry by access token.
     *
     * @param key CacheKey
     * @return Cached entry.
     */
    public AuthorizationGrantCacheEntry getValueFromCacheByToken(AuthorizationGrantCacheKey key) {
        AuthorizationGrantCacheEntry cacheEntry = super.getValueFromCache(key);
        if (cacheEntry == null) {
            cacheEntry = getFromSessionStore(replaceFromTokenId(key.getUserAttributesId()));
        }
        return cacheEntry;
    }

    /**
     * Clears a cache entry by access token.
     *
     * @param key Key to clear cache.
     */
    public void clearCacheEntryByToken(AuthorizationGrantCacheKey key) {
        super.clearCacheEntry(key);
        clearFromSessionStore(replaceFromTokenId(key.getUserAttributesId()));
    }

    /**
     * Clears a cache entry by tokenId
     *
     * @param key Key to clear cache.
     */
    public void clearCacheEntryByTokenId(AuthorizationGrantCacheKey key, String tokenId) {
        super.clearCacheEntry(key);
        clearFromSessionStore(tokenId);
    }

    /**
     * Add a cache entry by authorization code.
     *
     * @param key   Key which cache entry is indexed.
     * @param entry Actual object where cache entry is placed.
     */
    public void addToCacheByCode(AuthorizationGrantCacheKey key, AuthorizationGrantCacheEntry entry) {
        super.addToCache(key, entry);
        long validityPeriodNano = TimeUnit.SECONDS.toNanos(
                OAuthServerConfiguration.getInstance().getAuthorizationCodeValidityPeriodInSeconds());
        entry.setValidityPeriod(validityPeriodNano);
        storeToSessionStore(entry.getCodeId(), entry);
    }

    /**
     * Retrieves a cache entry by authorization code.
     *
     * @param key CacheKey
     * @return Cached entry.
     */
    public AuthorizationGrantCacheEntry getValueFromCacheByCode(AuthorizationGrantCacheKey key) {
        AuthorizationGrantCacheEntry cacheEntry = super.getValueFromCache(key);
        if (cacheEntry == null) {
            cacheEntry = getFromSessionStore(replaceFromCodeId(key.getUserAttributesId()));
        }
        return cacheEntry;
    }


    /**
     * Clears a cache entry by authorization code.
     *
     * @param key Key to clear cache.
     */
    public void clearCacheEntryByCode(AuthorizationGrantCacheKey key) {
        super.clearCacheEntry(key);
        clearFromSessionStore(replaceFromCodeId(key.getUserAttributesId()));
    }

    /**
     * Retrieve the authorization code id using the authorization code
     * @param authzCode Authorization code
     * @return CODE_ID from the database
     */
    private String replaceFromCodeId(String authzCode) {
        try {
            return OAuthTokenPersistenceFactory.getInstance().getAuthorizationCodeDAO()
                    .getCodeIdByAuthorizationCode(authzCode);
        } catch (IdentityOAuth2Exception e) {
            log.error("Failed to retrieve authorization code id by authorization code from store for - ." + authzCode, e);
        }
        return authzCode;
    }

    /**
     * Retrieve the access token id using the access token
     * @param keyValue Access token
     * @return TOKEN_ID from the database
     */
    private String replaceFromTokenId(String keyValue) {
        try {
            return OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO().getTokenIdByAccessToken(keyValue);
        } catch (IdentityOAuth2Exception e) {
            log.error("Failed to retrieve token id by token from store for - ." + keyValue, e);
        }
        return keyValue;
    }

    /**
     * Clears a cache entry from SessionDataStore.
     *
     * @param id to clear cache.
     */
    private void clearFromSessionStore(String id) {
        SessionDataStore.getInstance().clearSessionData(id, AUTHORIZATION_GRANT_CACHE_NAME);
    }

    /**
     * Retrieve cache entry from SessionDataStore
     * @param id session data key
     * @return
     */
    private AuthorizationGrantCacheEntry getFromSessionStore(String id) {
        return (AuthorizationGrantCacheEntry) SessionDataStore.getInstance().getSessionData(id,
                AUTHORIZATION_GRANT_CACHE_NAME);
    }

    /**
     * Store cache entry in SessionDataStore
     * @param id session data key
     * @param entry cache entry to store
     */
    private void storeToSessionStore(String id, AuthorizationGrantCacheEntry entry) {
        SessionDataStore.getInstance().storeSessionData(id, AUTHORIZATION_GRANT_CACHE_NAME, entry);
    }

}
