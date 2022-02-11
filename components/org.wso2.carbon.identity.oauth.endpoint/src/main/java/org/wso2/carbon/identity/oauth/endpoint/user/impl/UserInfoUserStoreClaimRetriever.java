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
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.user.UserInfoClaimRetriever;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Retrieving claims from the user store for the given claims dialect
 */
public class UserInfoUserStoreClaimRetriever implements UserInfoClaimRetriever {

    private static final String ATTRIBUTE_SEPARATOR = FrameworkUtils.getMultiAttributeSeparator();

    @Override
    public Map<String, Object> getClaimsMap(Map<ClaimMapping, String> userAttributes) {

        Map<String, Object> claims = new HashMap<String, Object>();
        if (MapUtils.isNotEmpty(userAttributes)) {
            for (Map.Entry<ClaimMapping, String> entry : userAttributes.entrySet()) {
                if (IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR.equals(entry.getKey().getRemoteClaim()
                        .getClaimUri())) {
                    continue;
                }
                if (OAuthServerConfiguration.getInstance().isEnableMultiValueSupport()) {
                    String claimValue = entry.getValue();
                    if (isMultiValuedAttribute(claimValue)) {
                        String[] attributeValues = entry.getValue().split(Pattern.quote(ATTRIBUTE_SEPARATOR));
                        claims.put(entry.getKey().getRemoteClaim().getClaimUri(), attributeValues);
                    } else {
                        claims.put(entry.getKey().getRemoteClaim().getClaimUri(), claimValue);
                    }
                } else {
                    claims.put(entry.getKey().getRemoteClaim().getClaimUri(), entry.getValue());
                }
            }
        }
        return claims;
    }

    /**
     * Check whether claim value is multi attribute or not by using attribute separator.
     *
     * @param claimValue String value contains claims.
     * @return Whether it is multi attribute or not.
     */
    private boolean isMultiValuedAttribute(String claimValue) {

        return StringUtils.contains(claimValue, ATTRIBUTE_SEPARATOR);
    }
}
