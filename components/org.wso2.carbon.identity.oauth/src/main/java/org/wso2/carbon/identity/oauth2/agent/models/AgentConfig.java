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

package org.wso2.carbon.identity.oauth2.agent.models;

/**
 * The AgentConfig class holds the tenant agent management configuration.
 */
public class AgentConfig {

    // A flag indicating whether the tenant's agents are managed in an external system.
    private boolean agentsExternallyManaged;

    /**
     * Gets whether the tenant's agents are externally managed.
     *
     * @return true if agents are externally managed, false otherwise.
     */
    public boolean isAgentsExternallyManaged() {

        return agentsExternallyManaged;
    }

    /**
     * Sets whether the tenant's agents are externally managed.
     *
     * @param agentsExternallyManaged true if agents are externally managed, false otherwise.
     */
    public void setAgentsExternallyManaged(boolean agentsExternallyManaged) {

        this.agentsExternallyManaged = agentsExternallyManaged;
    }
}
