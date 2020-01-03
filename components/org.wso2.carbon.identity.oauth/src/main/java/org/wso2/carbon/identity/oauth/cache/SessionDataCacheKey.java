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

/**
 * Session data cache key.
 */
public class SessionDataCacheKey extends CacheKey {

    private static final long serialVersionUID = -3480330645196653491L;
    private String sessionDataId;

    public SessionDataCacheKey(String sessionDataId) {
        this.sessionDataId = sessionDataId;
    }

    public String getSessionDataId() {
        return sessionDataId;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof SessionDataCacheKey)) {
            return false;
        }
        return this.sessionDataId.equals(((SessionDataCacheKey) o).getSessionDataId());
    }

    @Override
    public int hashCode() {
        return sessionDataId.hashCode();
    }
}
