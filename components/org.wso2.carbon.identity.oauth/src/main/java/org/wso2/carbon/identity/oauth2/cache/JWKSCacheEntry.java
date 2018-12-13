/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.cache;

import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.SecurityContext;

/**
 * JWKSCacheEntry wraps RemoteJWKSet cache value to make them serializable. This will be used with JWKSCache.
 */
public class JWKSCacheEntry extends org.wso2.carbon.identity.application.common.cache.CacheEntry {

    private transient RemoteJWKSet<SecurityContext> jwkSet;

    public JWKSCacheEntry(RemoteJWKSet<SecurityContext> jwkSet) {
        this.jwkSet = jwkSet;
    }

    public RemoteJWKSet<SecurityContext> getValue() {
        return jwkSet;
    }
}
