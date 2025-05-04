/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth2.finegrainedauthz.services;

import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.configuration.mgt.core.ConfigurationManager;
import org.wso2.carbon.identity.configuration.mgt.core.exception.ConfigurationManagementException;
import org.wso2.carbon.identity.configuration.mgt.core.model.Resource;
import org.wso2.carbon.identity.configuration.mgt.core.model.ResourceAdd;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth2.finegrainedauthz.exceptions.FineGrainedAuthzConfigMgtException;
import org.wso2.carbon.identity.oauth2.finegrainedauthz.models.FineGrainedAuthzConfig;
import org.wso2.carbon.identity.oauth2.finegrainedauthz.utils.Util;
import org.wso2.carbon.identity.oauth2.impersonation.utils.ErrorMessage;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;

import static org.wso2.carbon.identity.configuration.mgt.core.constant.ConfigurationConstants.ErrorMessages.ERROR_CODE_RESOURCE_DOES_NOT_EXISTS;
import static org.wso2.carbon.identity.oauth2.finegrainedauthz.utils.Util.handleClientException;
import static org.wso2.carbon.identity.oauth2.finegrainedauthz.utils.Util.handleServerException;

/**
 * Implementation of the FineGrainedAuthzConfigMgtService interface for managing
 * fine-grained authorization configurations.
 */
public class FineGrainedAuthzConfigMgtServiceImpl implements FineGrainedAuthzConfigMgtService {

    private static final String FINE_GRAINED_AUTHZ_RESOURCE_TYPE_NAME = "FINE_GRAINED_AUTHZ_CONFIGURATION";
    private static final String FINE_GRAINED_AUTHZ_RESOURCE_NAME = "TENANT_FINE_GRAINED_AUTHZ_CONFIGURATION";

    @Override
    public FineGrainedAuthzConfig getFineGrainedAuthzConfig(String tenantDomain)
            throws FineGrainedAuthzConfigMgtException {

        try {
            Resource resource = getResource(FINE_GRAINED_AUTHZ_RESOURCE_TYPE_NAME, FINE_GRAINED_AUTHZ_RESOURCE_NAME);
            FineGrainedAuthzConfig fineGrainedAuthzConfig;
            // If the resource is null, use the default configuration, otherwise parse the resource.
            if (resource == null) {
                fineGrainedAuthzConfig = Util.getDefaultConfiguration();
            } else {
                fineGrainedAuthzConfig = Util.parseResource(resource);
            }
            return fineGrainedAuthzConfig;
        } catch (ConfigurationManagementException e) {
            // If there is an error in retrieving the configuration, handle it as a server exception.
            throw handleServerException(ErrorMessage.ERROR_CODE_IMP_CONFIG_RETRIEVE, e, tenantDomain);
        }
    }

    @Override
    public void setFineGrainedAuthzConfig(FineGrainedAuthzConfig fineGrainedAuthzConfig, String tenantDomain)
            throws FineGrainedAuthzConfigMgtException {

        // Validate the tenant domain before proceeding.
        validateTenantDomain(tenantDomain);
        try {
            // Parse the impersonation configuration and replace the existing resource with the updated configuration.
            ResourceAdd resourceAdd = Util.parseConfig(fineGrainedAuthzConfig);
            getConfigurationManager().replaceResource(FINE_GRAINED_AUTHZ_RESOURCE_TYPE_NAME, resourceAdd);
        } catch (ConfigurationManagementException e) {
            // If there is an error in setting the configuration, handle it as a server exception.
            throw handleServerException(ErrorMessage.ERROR_CODE_INVALID_TENANT_DOMAIN, e, tenantDomain);
        }
    }

    /**
     * Validates the given tenant domain.
     *
     * @param tenantDomain The tenant domain to validate.
     * @throws FineGrainedAuthzConfigMgtException If the tenant domain is invalid.
     */
    private void validateTenantDomain(String tenantDomain) throws FineGrainedAuthzConfigMgtException {

        try {
            IdentityTenantUtil.getTenantId(tenantDomain);
        } catch (IdentityRuntimeException e) {
            throw handleClientException(ErrorMessage.ERROR_CODE_INVALID_TENANT_DOMAIN, e, tenantDomain);
        }
    }

    /**
     * Retrieves a resource based on the given resource type name and resource name.
     *
     * @param resourceTypeName The type name of the resource.
     * @param resourceName     The name of the resource.
     * @return The resource if found, or null if the resource does not exist.
     * @throws ConfigurationManagementException If there is an error in the configuration management process.
     */
    private Resource getResource(String resourceTypeName, String resourceName) throws ConfigurationManagementException {

        try {
            if (getConfigurationManager() != null) {
                return getConfigurationManager().getResource(resourceTypeName, resourceName);
            }
            return null;
        } catch (ConfigurationManagementException e) {
            if (ERROR_CODE_RESOURCE_DOES_NOT_EXISTS.getCode().equals(e.getErrorCode())) {
                return null;
            } else {
                throw e;
            }
        }
    }

    private ConfigurationManager getConfigurationManager() {

        return OAuth2ServiceComponentHolder.getInstance().getConfigurationManager();
    }
}
