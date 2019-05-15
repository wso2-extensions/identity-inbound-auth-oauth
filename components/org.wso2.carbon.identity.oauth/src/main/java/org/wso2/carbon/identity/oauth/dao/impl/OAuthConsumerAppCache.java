/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wso2.carbon.identity.oauth.dao.impl;

import org.wso2.carbon.identity.application.common.cache.BaseCache;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.utils.CarbonUtils;

/**
 * OAuthConsumerAppCache is used to cache OAuth2 consumer application information. Any reference to this cache should
 * be done through {@link CacheBackedOAuthConsumerAppDAO}.
 */
class OAuthConsumerAppCache extends BaseCache<String, OAuthAppDO> {


    private static final String OAUTH_CONSUMER_APP_CACHE_NAME = "OAuthConsumerAppCache";

    private static volatile OAuthConsumerAppCache instance;

    private OAuthConsumerAppCache() {
        super(OAUTH_CONSUMER_APP_CACHE_NAME);
    }

    /**
     * Returns OAuthConsumerAppCache instance.
     *
     * @return instance of OAuthConsumerAppCache
     */
    static OAuthConsumerAppCache getInstance() {
        CarbonUtils.checkSecurity();
        if (instance == null) {
            synchronized (OAuthConsumerAppCache.class) {
                if (instance == null) {
                    instance = new OAuthConsumerAppCache();
                }
            }
        }
        return instance;
    }
}
