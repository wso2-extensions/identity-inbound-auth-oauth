/*
 *  Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
 *
 *  WSO2 LLC. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.carbon.identity.oauth2.impersonation.services;

import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.configuration.mgt.core.ConfigurationManager;
import org.wso2.carbon.identity.configuration.mgt.core.exception.ConfigurationManagementException;
import org.wso2.carbon.identity.configuration.mgt.core.model.Resource;
import org.wso2.carbon.identity.configuration.mgt.core.model.ResourceAdd;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth2.impersonation.exceptions.ImpersonationConfigMgtException;
import org.wso2.carbon.identity.oauth2.impersonation.models.ImpersonationConfig;
import org.wso2.carbon.identity.oauth2.impersonation.utils.ErrorMessage;
import org.wso2.carbon.identity.oauth2.impersonation.utils.Util;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;

import static org.wso2.carbon.identity.configuration.mgt.core.constant.ConfigurationConstants.ErrorMessages.ERROR_CODE_RESOURCE_DOES_NOT_EXISTS;
import static org.wso2.carbon.identity.oauth2.impersonation.utils.Constants.IMPERSONATION_RESOURCE_NAME;
import static org.wso2.carbon.identity.oauth2.impersonation.utils.Constants.IMPERSONATION_RESOURCE_TYPE_NAME;
import static org.wso2.carbon.identity.oauth2.impersonation.utils.Util.handleClientException;
import static org.wso2.carbon.identity.oauth2.impersonation.utils.Util.handleServerException;

/**
 * Implementation class for managing impersonation configurations.
 */
public class ImpersonationConfigMgtServiceImpl implements ImpersonationConfigMgtService {

    /**
     * Retrieves the impersonation configuration for a given tenant domain.
     *
     * @param tenantDomain The domain of the tenant whose impersonation configuration is to be retrieved.
     * @return The impersonation configuration of the specified tenant.
     * @throws ImpersonationConfigMgtException If there is an error in retrieving the configuration.
     */
    @Override
    public ImpersonationConfig getImpersonationConfig(String tenantDomain) throws ImpersonationConfigMgtException {

        try {
            // Attempt to retrieve the resource containing impersonation configuration.
            Resource resource = getResource(IMPERSONATION_RESOURCE_TYPE_NAME, IMPERSONATION_RESOURCE_NAME);
            ImpersonationConfig impersonationConfig;
            // If the resource is null, use the default configuration, otherwise parse the resource.
            if (resource == null) {
                impersonationConfig = Util.getDefaultConfiguration();
            } else {
                impersonationConfig = Util.parseResource(resource);
            }
            return impersonationConfig;
        } catch (ConfigurationManagementException e) {
            // If there is an error in retrieving the configuration, handle it as a server exception.
            throw handleServerException(ErrorMessage.ERROR_CODE_IMP_CONFIG_RETRIEVE, e, tenantDomain);
        }
    }

    /**
     * Sets the impersonation configuration for a given tenant domain.
     *
     * @param impersonationConfig The impersonation configuration to be set.
     * @param tenantDomain        The domain of the tenant for which the configuration is to be set.
     * @throws ImpersonationConfigMgtException If there is an error in setting the configuration.
     */
    @Override
    public void setImpersonationConfig(ImpersonationConfig impersonationConfig, String tenantDomain)
            throws ImpersonationConfigMgtException {

        // Validate the tenant domain before proceeding.
        validateTenantDomain(tenantDomain);
        try {
            // Parse the impersonation configuration and replace the existing resource with the updated configuration.
            ResourceAdd resourceAdd = Util.parseConfig(impersonationConfig);
            getConfigurationManager().replaceResource(IMPERSONATION_RESOURCE_TYPE_NAME, resourceAdd);
        } catch (ConfigurationManagementException e) {
            // If there is an error in setting the configuration, handle it as a server exception.
            throw handleServerException(ErrorMessage.ERROR_CODE_IMP_CONFIG_UPDATE, e, tenantDomain);
        }
    }

    /**
     * Validates the given tenant domain.
     *
     * @param tenantDomain The tenant domain to validate.
     * @throws ImpersonationConfigMgtException If the tenant domain is invalid.
     */
    private void validateTenantDomain(String tenantDomain) throws ImpersonationConfigMgtException {

        try {
            IdentityTenantUtil.getTenantId(tenantDomain);
        } catch (IdentityRuntimeException e) {
            throw handleClientException(ErrorMessage.ERROR_CODE_INVALID_TENANT_DOMAIN, e, tenantDomain);
        }
    }

    /**
     * Retrieve the ConfigurationManager instance from the OAuth2ServiceComponentHolder.
     *
     * @return ConfigurationManager The ConfigurationManager instance.
     */
    private ConfigurationManager getConfigurationManager() {

        return OAuth2ServiceComponentHolder.getInstance().getConfigurationManager();
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
}
