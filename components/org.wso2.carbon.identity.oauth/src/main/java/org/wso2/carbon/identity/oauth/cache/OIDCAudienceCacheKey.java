/*
 *  Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wso2.carbon.identity.oauth.cache;

import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;

/**
 * @deprecated use {@link OAuthAppDO} to retrieve the audience. Then no need to consider caching for audience.
 */
public class OIDCAudienceCacheKey extends CacheKey {

    private static final long serialVersionUID = -4295443086275710946L;
    private String cacheKeyString;

    public OIDCAudienceCacheKey(String cacheKeyString) {
        this.cacheKeyString = cacheKeyString;
    }

    public String getCacheKeyString() {
        return cacheKeyString;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof OIDCAudienceCacheKey)) {
            return false;
        }
        return this.cacheKeyString.equals(((OIDCAudienceCacheKey) o).getCacheKeyString());
    }

    @Override
    public int hashCode() {
        return cacheKeyString.hashCode();
    }
}
