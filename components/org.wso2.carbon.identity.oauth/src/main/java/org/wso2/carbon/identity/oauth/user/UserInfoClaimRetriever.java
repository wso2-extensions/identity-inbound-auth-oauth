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
package org.wso2.carbon.identity.oauth.user;

import org.wso2.carbon.identity.application.common.model.ClaimMapping;

import java.util.Map;
import java.util.Set;

/**
 * Retrieving claims from the user store for the given claims dialect
 */
public interface UserInfoClaimRetriever {

    public Map<String, Object> getClaimsMap(Map<ClaimMapping, String> userAttributes);

    /**
     * Retrieve the claims map, honouring selective multi-valued claim handling. When
     * {@code multiValuedLocalClaimUris} is non-null, only claims flagged as multi-valued are emitted as arrays;
     * a {@code null} set falls back to legacy separator-based behaviour.
     *
     * @param userAttributes            User attributes keyed by claim mapping.
     * @param multiValuedLocalClaimUris Set of multi-valued claim URIs, or {@code null} for legacy behaviour.
     * @return Map of claims.
     */
    default Map<String, Object> getClaimsMap(Map<ClaimMapping, String> userAttributes,
                                             Set<String> multiValuedLocalClaimUris) {

        return getClaimsMap(userAttributes);
    }
}
