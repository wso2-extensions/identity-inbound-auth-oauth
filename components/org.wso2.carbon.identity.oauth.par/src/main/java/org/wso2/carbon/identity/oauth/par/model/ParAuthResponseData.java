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
 * Captures the values for response given by PAR Endpoint.
 */
public class ParAuthResponseData {

    private String reqUriRef;
    private long expiryTime;

    /**
     * Get request uri's uuid.
     *
     * @return reqUriUUID
     */
    public String getReqUriRef() {

        return reqUriRef;
    }

    /**
     * Get expiry time.
     *
     * @return expiryTime
     */
    public long getExpiryTime() {

        return expiryTime;
    }

    /**
     * Set uuid of request_uri.
     *
     * @param reqUriRef request uri's uuid
     */
    public void setReqUriRef(String reqUriRef) {

        this.reqUriRef = reqUriRef;
    }

    /**
     * Set expiry time.
     *
     * @param expiryTime expiry time
     */
    public void setExpiryTime(long expiryTime) {

        this.expiryTime = expiryTime;
    }
}
