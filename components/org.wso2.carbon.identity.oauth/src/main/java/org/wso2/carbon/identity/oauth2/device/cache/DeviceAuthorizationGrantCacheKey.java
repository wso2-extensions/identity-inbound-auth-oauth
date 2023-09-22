/*
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com)
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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.device.cache;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.oauth.cache.CacheKey;

/**
 * Device authorization grant cache key.
 */
public class DeviceAuthorizationGrantCacheKey extends CacheKey {

    private static final long serialVersionUID = 5025710840178743769L;
    private String cacheKeyString;

    public DeviceAuthorizationGrantCacheKey(String cacheKeyString) {

        this.cacheKeyString = cacheKeyString;
    }

    public String getCacheKeyString() {

        return cacheKeyString;
    }

    @Override
    public boolean equals(Object o) {

        if (!(o instanceof DeviceAuthorizationGrantCacheKey)) {
            return false;
        }
        return StringUtils.equals(this.cacheKeyString, ((DeviceAuthorizationGrantCacheKey) o).getCacheKeyString());
    }

    @Override
    public int hashCode() {

        return cacheKeyString.hashCode();
    }
}
