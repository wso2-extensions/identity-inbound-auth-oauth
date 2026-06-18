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

import org.wso2.carbon.identity.oauth2.agent.exceptions.AgentConfigMgtException;
import org.wso2.carbon.identity.oauth2.agent.models.AgentConfig;

/**
 * Service interface for managing tenant agent configurations.
 */
public interface AgentConfigMgtService {

    /**
     * Retrieves the agent configuration for a given tenant domain.
     *
     * @param tenantDomain The domain of the tenant whose agent configuration is to be retrieved.
     * @return The agent configuration of the specified tenant.
     * @throws AgentConfigMgtException If there is an error in retrieving the configuration.
     */
    AgentConfig getAgentConfig(String tenantDomain) throws AgentConfigMgtException;

    /**
     * Sets the agent configuration for a given tenant domain.
     *
     * @param agentConfig  The agent configuration to be set.
     * @param tenantDomain The domain of the tenant for which the configuration is to be set.
     * @throws AgentConfigMgtException If there is an error in setting the configuration.
     */
    void setAgentConfig(AgentConfig agentConfig, String tenantDomain)
            throws AgentConfigMgtException;

    /**
     * Deletes the agent configuration for a given tenant domain.
     *
     * @param tenantDomain The domain of the tenant whose agent configuration is to be deleted.
     * @throws AgentConfigMgtException If there is an error in deleting the configuration.
     */
    default void deleteAgentConfig(String tenantDomain) throws AgentConfigMgtException {}
}
