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

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.cache.AuthenticationBaseCache;
import org.wso2.carbon.identity.application.authentication.framework.store.SessionDataStore;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.utils.CarbonUtils;

import java.text.ParseException;
import java.util.concurrent.TimeUnit;

/**
 * Stores authenticated user attributes and OpenID Connect specific attributes during OIDC Authorization request
 * processing. Those values are later required to serve OIDC Token request and build IDToken.
 */
public class AuthorizationGrantCache extends
        AuthenticationBaseCache<AuthorizationGrantCacheKey, AuthorizationGrantCacheEntry> {

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
     * Retrieves cache entry by token id.
     *
     * @param key     AuthorizationGrantCacheKey
     * @param tokenId TokenId
     * @return AuthorizationGrantCacheEntry
     */
    public AuthorizationGrantCacheEntry getValueFromCacheByTokenId(AuthorizationGrantCacheKey key, String tokenId) {

        AuthorizationGrantCacheEntry cacheEntry = super.getValueFromCache(key);
        if (cacheEntry == null) {
            if (log.isDebugEnabled()) {
                log.debug("Getting cache entry from session store using tokenId: " + tokenId);
            }
            cacheEntry = getFromSessionStore(tokenId);
            if (cacheEntry != null) {
                super.addToCache(key, cacheEntry);
            }
        }
        return cacheEntry;
    }

    /**
     * Retrieves cache entry by token id and operation.
     *
     * @param key     AuthorizationGrantCacheKey
     * @param tokenId TokenId
     * @param operation Operation (STORE, DELETE)
     * @return AuthorizationGrantCacheEntry
     */
    public AuthorizationGrantCacheEntry getValueFromCacheByTokenId(AuthorizationGrantCacheKey key, String tokenId,
                                                                   String operation) {

        AuthorizationGrantCacheEntry cacheEntry = super.getValueFromCache(key);
        if (cacheEntry == null) {
            if (log.isDebugEnabled()) {
                log.debug("Getting cache entry from session store using tokenId: " + tokenId);
            }
            cacheEntry = getFromSessionStore(tokenId, operation);
            if (cacheEntry != null) {
                super.addToCache(key, cacheEntry);
            }
        }
        return cacheEntry;
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
            if (log.isDebugEnabled()) {
                if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                    log.debug("Getting cache entry from session store using access token(hashed): "
                            + DigestUtils.sha256Hex(key.getUserAttributesId()));
                } else {
                    log.debug("Getting cache entry from session store using access token");
                }
            }
            cacheEntry = getFromSessionStore(replaceFromTokenId(key.getUserAttributesId()));
            if (cacheEntry != null) {
                super.addToCache(key, cacheEntry);
            }
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
            if (log.isDebugEnabled()) {
                if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.AUTHORIZATION_CODE)) {
                    log.debug("Getting cache entry from session store using authorization code(hashed): "
                            + DigestUtils.sha256Hex(key.getUserAttributesId()));
                } else {
                    log.debug("Getting cache entry from session store using authorization code");
                }
            }
            cacheEntry = getFromSessionStore(replaceFromCodeId(key.getUserAttributesId()));
            if (cacheEntry != null) {
                super.addToCache(key, cacheEntry);
            }
        }
        return cacheEntry;
    }


    /**
     * Clears a cache entry by authorization code.
     *
     * @param key Key to clear cache.
     */
    public void clearCacheEntryByCode(AuthorizationGrantCacheKey key) {

        AuthorizationGrantCacheEntry valueFromCacheByCode = super.getValueFromCache(key);
        String codeId;
        if (valueFromCacheByCode != null) {
            codeId = valueFromCacheByCode.getCodeId();
            super.clearCacheEntry(key);
        } else {
            codeId = replaceFromCodeId(key.getUserAttributesId());
        }
        clearFromSessionStore(codeId);
    }

    /**
     * Clears a cache entry by authorization code Id.
     *
     * @param key         Key to clear cache
     * @param authzCodeId AuthorizationCodeId
     */
    public void clearCacheEntryByCodeId(AuthorizationGrantCacheKey key, String authzCodeId) {

        super.clearCacheEntry(key);
        clearFromSessionStore(authzCodeId);
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
            log.error("Failed to retrieve authorization code id by authorization code from store for - ." + authzCode,
                    e);
        }
        return authzCode;
    }

    /**
     * Retrieve the access token id using the access token
     * @param keyValue Access token
     * @return TOKEN_ID from the database
     */
    private String replaceFromTokenId(String keyValue) {
        if (OAuth2Util.isJWT(keyValue)) {
            try {
                JWT parsedJwtToken = JWTParser.parse(keyValue);
                keyValue = parsedJwtToken.getJWTClaimsSet().getJWTID();
            } catch (ParseException e) {
                if (log.isDebugEnabled()) {
                    if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                        log.debug("Error while getting JWTID from token: " + keyValue, e);
                    } else {
                        log.debug("Error while getting JWTID from token");
                    }
                }
            }
        }
        try {
            return OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO().getTokenIdByAccessToken(keyValue);
        } catch (IdentityOAuth2Exception e) {
            log.error("Failed to retrieve token id by token from store for - ." + keyValue, e);
        }
        return keyValue;
    }

    /**
     * Clears a cache entry from SessionDataStore if the id is not null.
     *
     * @param id to clear cache.
     */
    private void clearFromSessionStore(String id) {

        if (StringUtils.isNotBlank(id)) {
            SessionDataStore.getInstance().clearSessionData(id, AUTHORIZATION_GRANT_CACHE_NAME);
        }
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

    /**
     * Retrieve cache entry from SessionDataStore using the given operation.
     *
     * @param id session data key.
     * @param operation Operation (STORE, DELETE)
     * @return AuthorizationGrantCacheEntry.
     */
    private AuthorizationGrantCacheEntry getFromSessionStore(String id, String operation) {

        return (AuthorizationGrantCacheEntry) SessionDataStore.getInstance().getSessionData(id,
                AUTHORIZATION_GRANT_CACHE_NAME, operation);
    }
}
