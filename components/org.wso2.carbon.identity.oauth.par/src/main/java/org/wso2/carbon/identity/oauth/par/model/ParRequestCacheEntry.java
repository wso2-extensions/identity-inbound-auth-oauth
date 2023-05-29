/**
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com).
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
    private Map<String, String> params;
    private long scheduledExpiryTime;
    private String clientId;


    /**
     * Contractor for Cache entry of a PAR request.
     *
     * @param requestUri parameter map
     * @param params scheduled expiry time
     * @param scheduledExpiryTime client id
     */
    public ParRequestCacheEntry(String requestUri, Map<String, String> params, long scheduledExpiryTime) {

        this.requestUri = requestUri;
        this.params = params;
        this.scheduledExpiryTime = scheduledExpiryTime;
        this.clientId = params.get(OAuthConstants.OAuth20Params.CLIENT_ID);
    }

    /**
     * Get uuid of PAR request's request_uri.
     *
     * @return params
     */
    public String getRequestUri() {

        return requestUri;
    }

    /**
     * Get parameter map.
     *
     * @return params
     */
    public Map<String, String> getParams() {

        return params;
    }

    /**
     * Get scheduled expiry time.
     *
     * @return scheduledExpiryTime
     */
    public long getScheduledExpiryTime() {

        return scheduledExpiryTime;
    }

    /**
     * Get client id.
     *
     * @return clientId
     */
    public String getClientId() {

        return clientId;
    }

    /**
     * Set uuid of PAR request cache entry.
     *
     * @param requestUri request_uri uuid
     */
    public void setRequestUri(String requestUri) {

        this.requestUri = requestUri;
    }

    /**
     * Set parameter map.
     *
     * @param params parameter map
     */
    public void setParams(HashMap<String, String> params) {

        this.params = params;
    }

    /**
     * Set scheduled expiry.
     *
     * @param scheduledExpiryTime scheduled expiry
     */
    public void setScheduledExpiryTime(long scheduledExpiryTime) {

        this.scheduledExpiryTime = scheduledExpiryTime;
    }

    /**
     * Set client id.
     *
     * @param clientId client id
     */
    public void setClientId(String clientId) {

        this.clientId = clientId;
    }
}
