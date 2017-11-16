/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.identity.openidconnect;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.common.model.RoleMapping;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.apache.commons.collections.CollectionUtils.isNotEmpty;
import static org.apache.commons.lang.ArrayUtils.isNotEmpty;
import static org.apache.commons.lang.StringUtils.isNotBlank;

/**
 * Utility to handle OIDC Claim related functionality.
 */
public class OIDCClaimUtil {

    private OIDCClaimUtil() {
    }

    /**
     * Map the local roles of a user to service provider mapped role values.
     *
     * @param serviceProvider
     * @param locallyMappedUserRoles List of local roles
     * @param claimSeparator         Separator used to combine individual roles in the returned string.
     * @return Service Provider mapped roles combined with claimSeparator
     */
    public static String getServiceProviderMappedUserRoles(ServiceProvider serviceProvider,
                                                           List<String> locallyMappedUserRoles,
                                                           String claimSeparator) throws FrameworkException {
        if (isNotEmpty(locallyMappedUserRoles)) {
            locallyMappedUserRoles = new ArrayList<>(locallyMappedUserRoles);
            // Get Local Role to Service Provider Role mappings.
            RoleMapping[] localToSpRoleMapping = serviceProvider.getPermissionAndRoleConfig().getRoleMappings();

            if (isNotEmpty(localToSpRoleMapping)) {
                for (RoleMapping roleMapping : localToSpRoleMapping) {
                    // Check whether a local role is mapped to service provider role.
                    if (locallyMappedUserRoles.contains(getLocalRoleName(roleMapping))) {
                        // Remove the local roles from the list of user roles.
                        locallyMappedUserRoles.removeAll(Collections.singletonList(getLocalRoleName(roleMapping)));
                        // Add the service provider mapped role.
                        locallyMappedUserRoles.add(roleMapping.getRemoteRole());
                    }
                }
            }
            return StringUtils.join(locallyMappedUserRoles, claimSeparator);
        }
        return null;
    }

    public static String getSubjectClaimCachedAgainstAccessToken(String accessToken) {
        if (isNotBlank(accessToken)) {
            AuthorizationGrantCacheKey cacheKey = new AuthorizationGrantCacheKey(accessToken);
            AuthorizationGrantCacheEntry cacheEntry =
                    AuthorizationGrantCache.getInstance().getValueFromCacheByToken(cacheKey);
            if (cacheEntry != null) {
                return cacheEntry.getSubjectClaim();
            }
        }
        return null;
    }

    private static String getLocalRoleName(RoleMapping roleMapping) {
        return roleMapping.getLocalRole().getLocalRoleName();
    }
}
