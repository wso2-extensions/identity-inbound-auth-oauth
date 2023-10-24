/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth.cache;

import org.apache.commons.lang.StringUtils;

/**
 * Cache key for AppInfoCache.
 */
public class AppInfoCacheKey extends CacheKey {

    private static final long serialVersionUID = 4278123242830651680L;
    private final String consumerKey;
    private final int tenantId;

    public AppInfoCacheKey(String consumerKey, int tenantId) {

        this.consumerKey = consumerKey;
        this.tenantId = tenantId;
    }

    /**
     * Get the consumer key of the cache key.
     * @return Consumer key.
     */
    public String getConsumerKey() {

        return consumerKey;
    }

    /**
     * Get the tenant id of the cache key.
     * @return Tenant id.
     */
    public int getTenantId() {

        return tenantId;
    }

    @Override
    public boolean equals(Object o) {

        if (!(o instanceof AppInfoCacheKey)) {
            return false;
        }
        return StringUtils.equals(consumerKey, ((AppInfoCacheKey) o).getConsumerKey()) &&
                tenantId == ((AppInfoCacheKey) o).getTenantId();
    }

    @Override
    public int hashCode() {

        int result = consumerKey != null ? consumerKey.hashCode() : 0;
        return 31 * result + tenantId;
    }
}
