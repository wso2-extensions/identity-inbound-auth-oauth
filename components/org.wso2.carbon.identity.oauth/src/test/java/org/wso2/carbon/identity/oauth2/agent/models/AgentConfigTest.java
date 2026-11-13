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

import org.testng.annotations.Test;

import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

/**
 * Unit tests for {@link AgentConfig}.
 */
public class AgentConfigTest {

    @Test
    public void testDefaultsToLocallyManaged() {

        assertFalse(new AgentConfig().isAgentsExternallyManaged());
    }

    @Test
    public void testSetAgentsExternallyManaged() {

        AgentConfig agentConfig = new AgentConfig();
        agentConfig.setAgentsExternallyManaged(true);

        assertTrue(agentConfig.isAgentsExternallyManaged());
    }
}
