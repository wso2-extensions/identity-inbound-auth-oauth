/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth2.fapi.services;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.configuration.mgt.core.ConfigurationManager;
import org.wso2.carbon.identity.configuration.mgt.core.exception.ConfigurationManagementException;
import org.wso2.carbon.identity.configuration.mgt.core.model.Resource;
import org.wso2.carbon.identity.configuration.mgt.core.model.ResourceAdd;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth2.fapi.exceptions.FapiConfigMgtException;
import org.wso2.carbon.identity.oauth2.fapi.models.FapiConfig;
import org.wso2.carbon.identity.oauth2.fapi.utils.ErrorMessage;
import org.wso2.carbon.identity.oauth2.fapi.utils.FapiUtil;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;

import static org.wso2.carbon.identity.configuration.mgt.core.constant.ConfigurationConstants.ErrorMessages.ERROR_CODE_RESOURCE_DOES_NOT_EXISTS;
import static org.wso2.carbon.identity.oauth2.fapi.utils.Constants.FAPI_RESOURCE_NAME;
import static org.wso2.carbon.identity.oauth2.fapi.utils.Constants.FAPI_RESOURCE_TYPE_NAME;
import static org.wso2.carbon.identity.oauth2.fapi.utils.FapiUtil.handleClientException;
import static org.wso2.carbon.identity.oauth2.fapi.utils.FapiUtil.handleServerException;

/**
 * Implementation class for managing Financial-grade API (FAPI) configurations.
 */
public class FapiConfigMgtServiceImpl implements FapiConfigMgtService {

    private static final Log log = LogFactory.getLog(FapiConfigMgtServiceImpl.class);

    /**
     * Retrieves the FAPI configuration for a given tenant domain.
     *
     * @param tenantDomain The domain of the tenant whose FAPI configuration is to be retrieved.
     * @return The FAPI configuration of the specified tenant.
     * @throws FapiConfigMgtException If there is an error in retrieving the configuration.
     */
    @Override
    public FapiConfig getFapiConfig(String tenantDomain) throws FapiConfigMgtException {

        try {
            // Attempt to retrieve the resource containing FAPI configuration.
            final Resource resource = this.getFapiConfigResource();
            // If the resource is null, persist and return the default configuration, otherwise parse the resource.
            if (resource == null) {
                return FapiUtil.getDefaultConfiguration();
            }
            return FapiUtil.parseResource(resource);
        } catch (ConfigurationManagementException e) {
            throw handleServerException(ErrorMessage.ERROR_CODE_FAPI_CONFIG_RETRIEVE, e, tenantDomain);
        }
    }

    /**
     * Sets the FAPI configuration for a given tenant domain.
     *
     * @param fapiConfig   The FAPI configuration to be set.
     * @param tenantDomain The domain of the tenant for which the configuration is to be set.
     * @throws FapiConfigMgtException If there is an error in setting the configuration.
     */
    @Override
    public void setFapiConfig(FapiConfig fapiConfig, String tenantDomain) throws FapiConfigMgtException {

        validateTenantDomain(tenantDomain);
        validateFapiConfig(fapiConfig);
        try {
            // Parse the FAPI configuration and replace the existing resource with the updated configuration.
            ResourceAdd resourceAdd = FapiUtil.parseConfig(fapiConfig);
            getConfigurationManager().replaceResource(FAPI_RESOURCE_TYPE_NAME, resourceAdd);
        } catch (ConfigurationManagementException e) {
            throw handleServerException(ErrorMessage.ERROR_CODE_FAPI_CONFIG_UPDATE, e, tenantDomain);
        }
    }

    /**
     * Validates the given FAPI configuration.
     *
     * @param fapiConfig The FAPI configuration to validate.
     * @throws FapiConfigMgtException If the configuration is invalid.
     */
    private void validateFapiConfig(FapiConfig fapiConfig) throws FapiConfigMgtException {

        if (fapiConfig.isEnabled() && CollectionUtils.isEmpty(fapiConfig.getSupportedProfiles())) {
            throw handleClientException(ErrorMessage.ERROR_CODE_FAPI_ENABLED_WITH_EMPTY_PROFILES, null);
        }
    }

    /**
     * Validates the given tenant domain.
     *
     * @param tenantDomain The tenant domain to validate.
     * @throws FapiConfigMgtException If the tenant domain is invalid.
     */
    private void validateTenantDomain(String tenantDomain) throws FapiConfigMgtException {

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
     * Retrieves the fapi config resource.
     *
     * @return The resource if found, or null if the resource does not exist.
     * @throws ConfigurationManagementException If there is an error in the configuration management process.
     */
    private Resource getFapiConfigResource() throws ConfigurationManagementException {

        try {
            return this.getConfigurationManager().getResource(FAPI_RESOURCE_TYPE_NAME, FAPI_RESOURCE_NAME, true);
        } catch (ConfigurationManagementException e) {
            if (isResourceNotExistsError(e)) {
                if (log.isDebugEnabled()) {
                    log.debug(String.format("Resource does not exist. Caused by, %s", e.getMessage()));
                }
                return null;
            }
            throw e;
        }
    }

    private boolean isResourceNotExistsError(ConfigurationManagementException e) {

        return ERROR_CODE_RESOURCE_DOES_NOT_EXISTS.getCode().equals(e.getErrorCode());
    }

}
