/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth2.fapi.cache;

import org.wso2.carbon.identity.application.authentication.framework.cache.AuthenticationBaseCache;
import org.wso2.carbon.identity.oauth2.fapi.models.FapiConfig;
import org.wso2.carbon.utils.CarbonUtils;

/**
 * Cache for per-tenant FAPI configurations. Avoids a DB round-trip on every call to
 * {@code FapiConfigMgtService.getFapiConfig(tenantDomain)} which is invoked in hot auth paths.
 * TTL and capacity are configurable via identity.xml using the cache name "FapiConfigCache".
 */
public class FapiConfigCache extends AuthenticationBaseCache<String, FapiConfig> {

    private static final String FAPI_CONFIG_CACHE_NAME = "FapiConfigCache";

    private static volatile FapiConfigCache instance;

    private FapiConfigCache() {
        super(FAPI_CONFIG_CACHE_NAME);
    }

    public static FapiConfigCache getInstance() {
        CarbonUtils.checkSecurity();
        if (instance == null) {
            synchronized (FapiConfigCache.class) {
                if (instance == null) {
                    instance = new FapiConfigCache();
                }
            }
        }
        return instance;
    }
}
