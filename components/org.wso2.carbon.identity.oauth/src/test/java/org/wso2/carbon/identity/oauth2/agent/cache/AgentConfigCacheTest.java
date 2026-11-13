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

package org.wso2.carbon.identity.oauth2.agent.cache;

import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth2.agent.models.AgentConfig;

import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertSame;
import static org.testng.Assert.assertTrue;

/**
 * Unit tests for the agent configuration cache classes.
 */
public class AgentConfigCacheTest {

    @Test
    public void testGetInstanceReturnsSingleton() {

        AgentConfigCache instance = AgentConfigCache.getInstance();

        assertNotNull(instance);
        assertSame(AgentConfigCache.getInstance(), instance);
    }

    @Test
    public void testCacheEntryHoldsConfig() {

        AgentConfig agentConfig = new AgentConfig();
        agentConfig.setAgentsExternallyManaged(true);

        AgentConfigCacheEntry entry = new AgentConfigCacheEntry(agentConfig);

        assertSame(entry.getAgentConfig(), agentConfig);
        assertTrue(entry.getAgentConfig().isAgentsExternallyManaged());
    }

    @Test
    public void testCacheKeyCanBeCreated() {

        AgentConfigCacheKey key = new AgentConfigCacheKey("carbon.super");

        assertNotNull(key);
    }
}
