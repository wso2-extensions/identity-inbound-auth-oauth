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

import java.util.HashMap;
import java.util.Map;

/**
 * Object that holds data related to PAR request for caching.
 */
public class ParRequestCacheEntry extends CacheEntry {

    private String requestUri;
    private Map<String, String> params;
    private long expiresIn;
    private String clientId;


    /**
     * Contractor for Cache entry of a PAR request.
     *
     * @param requestUri Parameter map
     * @param params Scheduled expiry time
     * @param expiresIn Client id
     */
    public ParRequestCacheEntry(String requestUri, Map<String, String> params, long expiresIn, String clientId) {

        this.requestUri = requestUri;
        this.params = params;
        this.expiresIn = expiresIn;
        this.clientId = clientId;
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
     * @return expiresIn
     */
    public long getExpiresIn() {

        return expiresIn;
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
     * @param requestUri Request_uri uuid
     */
    public void setRequestUri(String requestUri) {

        this.requestUri = requestUri;
    }

    /**
     * Set parameter map.
     *
     * @param params Parameter map
     */
    public void setParams(HashMap<String, String> params) {

        this.params = params;
    }

    /**
     * Set scheduled expiry.
     *
     * @param expiresIn Scheduled expiry
     */
    public void setExpiresIn(long expiresIn) {

        this.expiresIn = expiresIn;
    }

    /**
     * Set client id.
     *
     * @param clientId Client id
     */
    public void setClientId(String clientId) {

        this.clientId = clientId;
    }
}
