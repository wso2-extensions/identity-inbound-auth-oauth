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

import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.oauth.cache.CacheEntry;

import java.util.Map;

/**
 * Contains authenticated user attributes.
 */
public class DeviceAuthorizationGrantCacheEntry extends CacheEntry {

    private static final long serialVersionUID = -3043225645166013281L;

    private Map<ClaimMapping, String> userAttributes;
    private Map<ClaimMapping, String> mappedRemoteClaims;

    public DeviceAuthorizationGrantCacheEntry(Map<ClaimMapping, String> userAttributes) {

        this.userAttributes = userAttributes;
    }

    /**
     * Return user attributes of cache entry.
     *
     * @return User attributes.
     */
    public Map<ClaimMapping, String> getUserAttributes() {

        return userAttributes;
    }

    /**
     * Set user attributes of cache entry.
     *
     * @param userAttributes User attributes to be set to the cache entry.
     */
    public void setUserAttributes(Map<ClaimMapping, String> userAttributes) {

        this.userAttributes = userAttributes;
    }

    public Map<ClaimMapping, String> getMappedRemoteClaims() {

        return mappedRemoteClaims;
    }

    public void setMappedRemoteClaims(
            Map<ClaimMapping, String> mappedRemoteClaims) {

        this.mappedRemoteClaims = mappedRemoteClaims;
    }
}
