/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth2.scopeservice;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.api.resource.mgt.APIResourceMgtException;
import org.wso2.carbon.identity.application.common.model.APIResource;
import org.wso2.carbon.identity.application.common.model.Scope;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ScopeServerException;
import org.wso2.carbon.identity.oauth2.Oauth2ScopeConstants;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.util.Oauth2ScopeUtils;

import java.util.List;
import java.util.stream.Collectors;

/**
 * API Resource based scope metadata service implementation.
 */
public class APIResourceBasedScopeMetadataService implements ScopeMetadataService {

    @Override
    public List<OAuth2Resource> getMetadata(List<String> permissions) throws IdentityOAuth2ScopeServerException {

        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        if (StringUtils.isEmpty(tenantDomain)) {
            throw new IdentityOAuth2ScopeServerException("Cannot retrieve the tenant domain.");
        }

        List<APIResource> apiMetadataList;
        try {
            apiMetadataList = OAuth2ServiceComponentHolder.getInstance().getApiResourceManager()
                    .getScopeMetadata(permissions, tenantDomain);
        } catch (APIResourceMgtException e) {
            throw Oauth2ScopeUtils.generateServerException(Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_FAILED_TO_GET_SCOPE_METADATA, e);
        }

        List<OAuth2Resource> resources = apiMetadataList.stream()
                .map(apiMetadata -> {
                    OAuth2Resource resource = new OAuth2Resource();
                    resource.setName(apiMetadata.getName());
                    resource.setId(apiMetadata.getId());
                    resource.setScopes(mapScopes(apiMetadata.getScopes()));
                    return resource;
                }).collect(Collectors.toList());
        return resources;
    }

    /**
     * Map APIResource scopes to ScopeMetadata.
     *
     * @param scopes List of scopes.
     * @return List of ScopeMetadata.
     */
    private List<ScopeMetadata> mapScopes(List<Scope> scopes) {

        return scopes.stream()
                .map(scope -> {
                    ScopeMetadata scopeMetadata = new ScopeMetadata();
                    scopeMetadata.setIdentifier(scope.getName());
                    scopeMetadata.setDisplayName(scope.getDisplayName());
                    scopeMetadata.setDescription(scope.getDescription());
                    return scopeMetadata;
                }).collect(Collectors.toList());
    }
}
