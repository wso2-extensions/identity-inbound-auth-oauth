/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.cache;


import java.io.Serializable;

/**
 * Key attribute of JWKSCache is jwksUri. JWKS cache is stored against this key.
 */
public class JWKSCacheKey implements Serializable {

    private static final long serialVersionUID = 5023478840178743769L;
    private String jwksUri;

    public JWKSCacheKey(String jwksUri) {
        this.jwksUri = jwksUri;
    }

    public String getJWKSCacheKey() {
        return jwksUri;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof JWKSCacheKey)) {
            return false;
        }
        return this.jwksUri.equals(((JWKSCacheKey) o).getJWKSCacheKey());
    }

    @Override
    public int hashCode() {
        return jwksUri.hashCode();
    }
}
