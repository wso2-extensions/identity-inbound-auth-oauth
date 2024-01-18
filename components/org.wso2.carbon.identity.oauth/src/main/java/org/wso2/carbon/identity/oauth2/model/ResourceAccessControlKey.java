/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth2.model;

import java.util.Objects;

/**
 * This class represents the key for the resource access control map.
 */
public class ResourceAccessControlKey {

    private String endpointRegex;
    private String httpMethod;

    /**
     * Get the endpoint regex.
     *
     * @return endpoint regex.
     */
    public String getEndpointRegex() {

        return endpointRegex;
    }

    /**
     * Set the endpoint regex.
     *
     * @param endpointRegex Endpoint regex.
     */
    public void setEndpointRegex(String endpointRegex) {

        this.endpointRegex = endpointRegex;
    }

    /**
     * Get the http method.
     *
     * @return Http method.
     */
    public String getHttpMethod() {

        return httpMethod;
    }

    /**
     * Set the http method.
     *
     * @param httpMethod Http method.
     */
    public void setHttpMethod(String httpMethod) {

        this.httpMethod = httpMethod;
    }

    @Override
    public boolean equals(Object o) {

        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        ResourceAccessControlKey that = (ResourceAccessControlKey) o;
        return Objects.equals(endpointRegex, that.endpointRegex) && Objects.equals(httpMethod, that.httpMethod);
    }

    @Override
    public int hashCode() {

        return Objects.hash(endpointRegex, httpMethod);
    }
}
