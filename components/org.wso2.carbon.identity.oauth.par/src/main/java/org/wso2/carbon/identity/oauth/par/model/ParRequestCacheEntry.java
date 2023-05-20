/**
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com). All Rights Reserved.
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.par.model;

import org.wso2.carbon.identity.core.cache.CacheEntry;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;

import java.util.HashMap;
import java.util.Map;

/**
 * PAR request with all attributes for caching.
 */
public class ParRequestCacheEntry extends CacheEntry {

    private String requestUri;
    private Map<String, String> parameterMap;
    private long scheduledExpiryTime;
    private String clientId;


    public ParRequestCacheEntry(String requestUri, Map<String, String> parameterMap, long scheduledExpiryTime) {

        this.requestUri = requestUri;
        this.parameterMap = parameterMap;
        this.scheduledExpiryTime = scheduledExpiryTime;
        this.clientId = parameterMap.get(OAuthConstants.OAuth20Params.CLIENT_ID);
    }

    public String getRequestUri() {

        return requestUri;
    }

    public Map<String, String> getParameterMap() {

        return parameterMap;
    }

    public long getScheduledExpiryTime() {

        return scheduledExpiryTime;
    }

    public String getClientId() {

        return clientId;
    }

    public void setRequestUri(String requestUri) {

        this.requestUri = requestUri;
    }

    public void setParameterMap(HashMap<String, String> parameterMap) {

        this.parameterMap = parameterMap;
    }

    public void setScheduledExpiryTime(long scheduledExpiryTime) {

        this.scheduledExpiryTime = scheduledExpiryTime;
    }

    public void setClientId(String clientId) {

        this.clientId = clientId;
    }
}
