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

package org.wso2.carbon.identity.oauth2.agent.utils;

import org.apache.commons.collections.CollectionUtils;
import org.wso2.carbon.identity.configuration.mgt.core.model.Attribute;
import org.wso2.carbon.identity.configuration.mgt.core.model.Resource;
import org.wso2.carbon.identity.configuration.mgt.core.model.ResourceAdd;
import org.wso2.carbon.identity.oauth2.agent.exceptions.AgentConfigMgtClientException;
import org.wso2.carbon.identity.oauth2.agent.exceptions.AgentConfigMgtException;
import org.wso2.carbon.identity.oauth2.agent.exceptions.AgentConfigMgtServerException;
import org.wso2.carbon.identity.oauth2.agent.models.AgentConfig;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.wso2.carbon.identity.oauth2.agent.utils.Constants.AGENTS_EXTERNALLY_MANAGED;
import static org.wso2.carbon.identity.oauth2.agent.utils.Constants.AGENT_RESOURCE_NAME;

/**
 * Utility class providing helper methods for managing tenant agent configurations.
 */
public class Util {

    private static final boolean AGENTS_EXTERNALLY_MANAGED_DEFAULT = false;

    /**
     * Handles server exceptions by creating an instance of AgentConfigMgtServerException.
     *
     * @param error The error message and code associated with the server exception.
     * @param e     The underlying cause of the server exception.
     * @param data  Additional data to be included in the error message.
     * @return An instance of AgentConfigMgtServerException.
     */
    public static AgentConfigMgtException handleServerException(ErrorMessage error, Throwable e, String... data) {

        return new AgentConfigMgtServerException(String.format(error.getDescription(), data), error.getCode(), e);
    }

    /**
     * Handles client exceptions by creating an instance of AgentConfigMgtClientException.
     *
     * @param error The error message and code associated with the client exception.
     * @param e     The underlying cause of the client exception.
     * @param data  Additional data to be included in the error message.
     * @return An instance of AgentConfigMgtClientException.
     */
    public static AgentConfigMgtException handleClientException(ErrorMessage error, Throwable e, String... data) {

        return new AgentConfigMgtClientException(String.format(error.getDescription(), data), error.getCode(), e);
    }

    /**
     * Parses an AgentConfig object into a ResourceAdd object.
     *
     * @param agentConfig The agent configuration to be parsed.
     * @return A ResourceAdd object representing the parsed configuration.
     */
    public static ResourceAdd parseConfig(AgentConfig agentConfig) {

        ResourceAdd resourceAdd = new ResourceAdd();
        resourceAdd.setName(AGENT_RESOURCE_NAME);
        List<Attribute> attributes = new ArrayList<>();
        Attribute attribute = new Attribute();
        attribute.setKey(AGENTS_EXTERNALLY_MANAGED);
        attribute.setValue(String.valueOf(agentConfig.isAgentsExternallyManaged()));
        attributes.add(attribute);
        resourceAdd.setAttributes(attributes);
        return resourceAdd;
    }

    /**
     * Parses a Resource object into an AgentConfig object.
     *
     * @param resource The resource to be parsed.
     * @return An AgentConfig object representing the parsed resource.
     */
    public static AgentConfig parseResource(Resource resource) {

        AgentConfig agentConfig = new AgentConfig();
        if (resource.isHasAttribute()) {
            Map<String, String> attributeMap = getAttributeMap(resource.getAttributes());
            agentConfig.setAgentsExternallyManaged(
                    Boolean.parseBoolean(attributeMap.get(AGENTS_EXTERNALLY_MANAGED)));
        }
        return agentConfig;
    }

    private static Map<String, String> getAttributeMap(List<Attribute> attributes) {

        if (CollectionUtils.isNotEmpty(attributes)) {
            return attributes.stream().collect(Collectors.toMap(Attribute::getKey, Attribute::getValue));
        }
        return Collections.emptyMap();
    }

    /**
     * Retrieves the default agent configuration. Agents are managed locally by default.
     *
     * @return The default AgentConfig object.
     */
    public static AgentConfig getDefaultConfiguration() {

        AgentConfig agentConfig = new AgentConfig();
        agentConfig.setAgentsExternallyManaged(AGENTS_EXTERNALLY_MANAGED_DEFAULT);
        return agentConfig;
    }
}
