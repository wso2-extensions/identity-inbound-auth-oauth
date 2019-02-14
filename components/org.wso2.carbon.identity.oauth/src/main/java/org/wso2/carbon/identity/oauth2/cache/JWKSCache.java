/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.cache;

import org.wso2.carbon.identity.application.common.cache.BaseCache;
import org.wso2.carbon.utils.CarbonUtils;

/**
 * JWKS cache enables caching responses from JWK URIs
 */
public class JWKSCache extends BaseCache<JWKSCacheKey, JWKSCacheEntry> {

    private static final String JWKS_CACHE_NAME = "JWKSCache";

    private static volatile JWKSCache instance;

    private JWKSCache() {
        super(JWKS_CACHE_NAME);
    }

    /**
     * Returns JWKSCache instance
     *
     * @return instance of JWKSCache
     */
    public static JWKSCache getInstance() {
        CarbonUtils.checkSecurity();
        if (instance == null) {
            synchronized (JWKSCache.class) {
                if (instance == null) {
                    instance = new JWKSCache();
                }
            }
        }
        return instance;
    }
}
