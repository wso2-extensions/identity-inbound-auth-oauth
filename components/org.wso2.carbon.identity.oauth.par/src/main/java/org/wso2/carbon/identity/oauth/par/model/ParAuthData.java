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

/**
 * Captures the values for response given by PAR auth service.
 */
public class ParAuthData {

    private String requestURIReference;
    private long expiryTime;

    /**
     * Get request uri's uuid.
     *
     * @return Uuid of request uri.
     */
    public String getrequestURIReference() {

        return requestURIReference;
    }

    /**
     * Get expiry time.
     *
     * @return Scheduled expiry time.
     */
    public long getExpiryTime() {

        return expiryTime;
    }

    /**
     * Set uuid of request uri.
     *
     * @param requestURIReference Request uri's uuid.
     */
    public void setrequestURIReference(String requestURIReference) {

        this.requestURIReference = requestURIReference;
    }

    /**
     * Set expiry time.
     *
     * @param expiryTime Expiry time.
     */
    public void setExpiryTime(long expiryTime) {

        this.expiryTime = expiryTime;
    }
}
