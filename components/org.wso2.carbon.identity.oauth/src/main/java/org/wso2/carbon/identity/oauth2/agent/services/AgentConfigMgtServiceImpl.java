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

package org.wso2.carbon.identity.oauth2.agent.services;

import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.configuration.mgt.core.ConfigurationManager;
import org.wso2.carbon.identity.configuration.mgt.core.exception.ConfigurationManagementException;
import org.wso2.carbon.identity.configuration.mgt.core.model.Resource;
import org.wso2.carbon.identity.configuration.mgt.core.model.ResourceAdd;
import org.wso2.carbon.identity.configuration.mgt.core.model.ResourceTypeAdd;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth2.agent.cache.AgentConfigCache;
import org.wso2.carbon.identity.oauth2.agent.cache.AgentConfigCacheEntry;
import org.wso2.carbon.identity.oauth2.agent.cache.AgentConfigCacheKey;
import org.wso2.carbon.identity.oauth2.agent.exceptions.AgentConfigMgtException;
import org.wso2.carbon.identity.oauth2.agent.models.AgentConfig;
import org.wso2.carbon.identity.oauth2.agent.utils.ErrorMessage;
import org.wso2.carbon.identity.oauth2.agent.utils.Util;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;

import static org.wso2.carbon.identity.configuration.mgt.core.constant.ConfigurationConstants.ErrorMessages.ERROR_CODE_RESOURCE_DOES_NOT_EXISTS;
import static org.wso2.carbon.identity.configuration.mgt.core.constant.ConfigurationConstants.ErrorMessages.ERROR_CODE_RESOURCE_TYPE_ALREADY_EXISTS;
import static org.wso2.carbon.identity.configuration.mgt.core.constant.ConfigurationConstants.ErrorMessages.ERROR_CODE_RESOURCE_TYPE_DOES_NOT_EXISTS;
import static org.wso2.carbon.identity.oauth2.agent.utils.Constants.AGENT_RESOURCE_NAME;
import static org.wso2.carbon.identity.oauth2.agent.utils.Constants.AGENT_RESOURCE_TYPE_DESCRIPTION;
import static org.wso2.carbon.identity.oauth2.agent.utils.Constants.AGENT_RESOURCE_TYPE_NAME;
import static org.wso2.carbon.identity.oauth2.agent.utils.Util.handleClientException;
import static org.wso2.carbon.identity.oauth2.agent.utils.Util.handleServerException;

/**
 * Implementation class for managing tenant agent configurations.
 */
public class AgentConfigMgtServiceImpl implements AgentConfigMgtService {

    /**
     * Retrieves the agent configuration for a given tenant domain.
     *
     * @param tenantDomain The domain of the tenant whose agent configuration is to be retrieved.
     * @return The agent configuration of the specified tenant.
     * @throws AgentConfigMgtException If there is an error in retrieving the configuration.
     */
    @Override
    public AgentConfig getAgentConfig(String tenantDomain) throws AgentConfigMgtException {

        // Serve from cache when available, including the cached default configuration.
        AgentConfig cachedConfig = getAgentConfigFromCache(tenantDomain);
        if (cachedConfig != null) {
            return cachedConfig;
        }

        AgentConfig agentConfig;
        try {
            // A missing resource maps to the default configuration.
            Resource resource = getResource(AGENT_RESOURCE_TYPE_NAME, AGENT_RESOURCE_NAME);
            agentConfig = resource == null ? Util.getDefaultConfiguration() : Util.parseResource(resource);
        } catch (ConfigurationManagementException e) {
            throw handleServerException(ErrorMessage.ERROR_CODE_AGENT_CONFIG_RETRIEVE, e, tenantDomain);
        }
        addAgentConfigToCacheOnRead(agentConfig, tenantDomain);
        return agentConfig;
    }

    /**
     * Sets the agent configuration for a given tenant domain.
     *
     * @param agentConfig  The agent configuration to be set.
     * @param tenantDomain The domain of the tenant for which the configuration is to be set.
     * @throws AgentConfigMgtException If there is an error in setting the configuration.
     */
    @Override
    public void setAgentConfig(AgentConfig agentConfig, String tenantDomain)
            throws AgentConfigMgtException {

        validateTenantDomain(tenantDomain);
        try {
            ResourceAdd resourceAdd = Util.parseConfig(agentConfig);
            replaceResource(resourceAdd);
            clearAgentConfigCache(tenantDomain);
        } catch (ConfigurationManagementException e) {
            throw handleServerException(ErrorMessage.ERROR_CODE_AGENT_CONFIG_UPDATE, e, tenantDomain);
        }
    }

    /**
     * Deletes the agent configuration for a given tenant domain.
     *
     * @param tenantDomain The domain of the tenant whose agent configuration is to be deleted.
     * @throws AgentConfigMgtException If there is an error in deleting the configuration.
     */
    @Override
    public void deleteAgentConfig(String tenantDomain) throws AgentConfigMgtException {

        validateTenantDomain(tenantDomain);
        try {
            Resource resource = getResource(AGENT_RESOURCE_TYPE_NAME, AGENT_RESOURCE_NAME);
            if (resource != null) {
                getConfigurationManager().deleteResource(AGENT_RESOURCE_TYPE_NAME, AGENT_RESOURCE_NAME);
                clearAgentConfigCache(tenantDomain);
            }
        } catch (ConfigurationManagementException e) {
            throw handleServerException(ErrorMessage.ERROR_CODE_AGENT_CONFIG_DELETE, e, tenantDomain);
        }
    }

    /**
     * Validates the given tenant domain.
     *
     * @param tenantDomain The tenant domain to validate.
     * @throws AgentConfigMgtException If the tenant domain is invalid.
     */
    private void validateTenantDomain(String tenantDomain) throws AgentConfigMgtException {

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
    private Resource getResource(String resourceTypeName, String resourceName)
            throws ConfigurationManagementException {

        try {
            if (getConfigurationManager() != null) {
                return getConfigurationManager().getResource(resourceTypeName, resourceName, true);
            }
            return null;
        } catch (ConfigurationManagementException e) {
            if (ERROR_CODE_RESOURCE_DOES_NOT_EXISTS.getCode().equals(e.getErrorCode()) ||
                    ERROR_CODE_RESOURCE_TYPE_DOES_NOT_EXISTS.getCode().equals(e.getErrorCode())) {
                return null;
            }
            throw e;
        }
    }

    /**
     * Persists the agent configuration resource, creating the resource type on demand if it does not yet exist.
     *
     * @param resourceAdd The resource to persist.
     * @throws ConfigurationManagementException If there is an error in the configuration management process.
     */
    private void replaceResource(ResourceAdd resourceAdd) throws ConfigurationManagementException {

        try {
            getConfigurationManager().replaceResource(AGENT_RESOURCE_TYPE_NAME, resourceAdd);
        } catch (ConfigurationManagementException e) {
            if (ERROR_CODE_RESOURCE_TYPE_DOES_NOT_EXISTS.getCode().equals(e.getErrorCode())) {
                createResourceType();
                getConfigurationManager().replaceResource(AGENT_RESOURCE_TYPE_NAME, resourceAdd);
                return;
            }
            throw e;
        }
    }

    /**
     * Creates the agent configuration resource type.
     *
     * @throws ConfigurationManagementException If there is an error in creating the resource type.
     */
    private void createResourceType() throws ConfigurationManagementException {

        try {
            ResourceTypeAdd resourceType = new ResourceTypeAdd();
            resourceType.setName(AGENT_RESOURCE_TYPE_NAME);
            resourceType.setDescription(AGENT_RESOURCE_TYPE_DESCRIPTION);
            getConfigurationManager().addResourceType(resourceType);
        } catch (ConfigurationManagementException e) {
            if (!ERROR_CODE_RESOURCE_TYPE_ALREADY_EXISTS.getCode().equals(e.getErrorCode())) {
                throw e;
            }
        }
    }

    private AgentConfig getAgentConfigFromCache(String tenantDomain) {

        AgentConfigCacheKey cacheKey = new AgentConfigCacheKey(tenantDomain);
        AgentConfigCacheEntry cacheEntry = AgentConfigCache.getInstance().getValueFromCache(cacheKey, tenantDomain);
        if (cacheEntry != null) {
            return cacheEntry.getAgentConfig();
        }
        return null;
    }

    private void addAgentConfigToCacheOnRead(AgentConfig agentConfig, String tenantDomain) {

        AgentConfigCacheKey cacheKey = new AgentConfigCacheKey(tenantDomain);
        AgentConfigCacheEntry cacheEntry = new AgentConfigCacheEntry(agentConfig);
        AgentConfigCache.getInstance().addToCacheOnRead(cacheKey, cacheEntry, tenantDomain);
    }

    private void clearAgentConfigCache(String tenantDomain) {

        AgentConfigCacheKey cacheKey = new AgentConfigCacheKey(tenantDomain);
        AgentConfigCache.getInstance().clearCacheEntry(cacheKey, tenantDomain);
    }
}
