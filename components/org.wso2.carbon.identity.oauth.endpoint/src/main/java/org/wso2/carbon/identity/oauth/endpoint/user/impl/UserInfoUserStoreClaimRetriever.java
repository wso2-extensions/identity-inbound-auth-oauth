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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.oauth.endpoint.user.impl;

import org.apache.commons.collections.MapUtils;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.claim.metadata.mgt.model.LocalClaim;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.endpoint.util.ClaimUtil;
import org.wso2.carbon.identity.oauth.user.UserInfoClaimRetriever;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.util.HashMap;
import java.util.Map;

/**
 * Retrieving claims from the user store for the given claims dialect
 */
public class UserInfoUserStoreClaimRetriever implements UserInfoClaimRetriever {

    @Override
    public Map<String, Object> getClaimsMap(Map<ClaimMapping, String> userAttributes) {

        Map<String, Object> claims = new HashMap<String, Object>();
        if (MapUtils.isNotEmpty(userAttributes)) {
            Map<String, LocalClaim> mappedLocalClaims =
                    OAuthServerConfiguration.getInstance().isHonorMultivaluedClaimMetadata()
                            ? OAuth2Util.getMappedLocalClaims(PrivilegedCarbonContext
                            .getThreadLocalCarbonContext().getTenantDomain()) : null;
            for (Map.Entry<ClaimMapping, String> entry : userAttributes.entrySet()) {

                if (entry.getKey().getRemoteClaim() == null || IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR.equals(
                        entry.getKey().getRemoteClaim().getClaimUri())) {
                    continue;
                }
                String claimValue = entry.getValue();
                String claimUri = entry.getKey().getRemoteClaim().getClaimUri();
                String localClaimUri = entry.getKey().getLocalClaim() == null ? null
                        : entry.getKey().getLocalClaim().getClaimUri();
                boolean isMultiValueSupportEnabledForUserinfoResponse = OAuthServerConfiguration.getInstance()
                        .getUserInfoMultiValueSupportEnabled();
                if (isMultiValueSupportEnabledForUserinfoResponse &&
                        ClaimUtil.isMultiValuedAttribute(claimUri, localClaimUri, claimValue, mappedLocalClaims)) {
                    String[] attributeValues = ClaimUtil.processMultiValuedAttribute(claimValue);
                    claims.put(claimUri, attributeValues);
                } else {
                    claims.put(claimUri, claimValue);
                }
            }
        }
        return claims;
    }
}
