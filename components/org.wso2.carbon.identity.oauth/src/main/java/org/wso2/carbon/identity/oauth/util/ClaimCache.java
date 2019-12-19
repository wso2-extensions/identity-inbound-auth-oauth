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

package org.wso2.carbon.identity.oauth.util;


import org.wso2.carbon.identity.application.common.cache.BaseCache;
import org.wso2.carbon.identity.oauth.listener.ClaimCacheRemoveListener;
import org.wso2.carbon.utils.CarbonUtils;

/**
 * User claim cache key.
 */
public class ClaimCache extends BaseCache<ClaimCacheKey, UserClaims> {

    private static final String CLAIM_CACHE_NAME = "ClaimCache";

    private static ClaimCache instance;

    private ClaimCache() {
        super(CLAIM_CACHE_NAME);
        super.addListener(new ClaimCacheRemoveListener());
    }

    public static ClaimCache getInstance() {
        CarbonUtils.checkSecurity();
        if (instance == null) {
            synchronized (ClaimCache.class) {
                if (instance == null) {
                    instance = new ClaimCache();
                }
            }
        }
        return instance;
    }
}
