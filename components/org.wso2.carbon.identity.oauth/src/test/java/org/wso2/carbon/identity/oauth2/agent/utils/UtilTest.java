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

import org.testng.annotations.Test;
import org.wso2.carbon.identity.configuration.mgt.core.model.Attribute;
import org.wso2.carbon.identity.configuration.mgt.core.model.Resource;
import org.wso2.carbon.identity.configuration.mgt.core.model.ResourceAdd;
import org.wso2.carbon.identity.oauth2.agent.exceptions.AgentConfigMgtClientException;
import org.wso2.carbon.identity.oauth2.agent.exceptions.AgentConfigMgtException;
import org.wso2.carbon.identity.oauth2.agent.exceptions.AgentConfigMgtServerException;
import org.wso2.carbon.identity.oauth2.agent.models.AgentConfig;

import java.util.Collections;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;
import static org.wso2.carbon.identity.oauth2.agent.utils.Constants.AGENTS_EXTERNALLY_MANAGED;
import static org.wso2.carbon.identity.oauth2.agent.utils.Constants.AGENT_RESOURCE_NAME;

/**
 * Unit tests for {@link Util}.
 */
public class UtilTest {

    @Test
    public void testHandleServerException() {

        Throwable cause = new RuntimeException("root");
        AgentConfigMgtException e = Util.handleServerException(
                ErrorMessage.ERROR_CODE_AGENT_CONFIG_RETRIEVE, cause, "carbon.super");

        assertTrue(e instanceof AgentConfigMgtServerException);
        assertEquals(e.getErrorCode(), ErrorMessage.ERROR_CODE_AGENT_CONFIG_RETRIEVE.getCode());
        assertTrue(e.getMessage().contains("carbon.super"));
        assertEquals(e.getCause(), cause);
    }

    @Test
    public void testHandleClientException() {

        Throwable cause = new RuntimeException("root");
        AgentConfigMgtException e = Util.handleClientException(
                ErrorMessage.ERROR_CODE_INVALID_TENANT_DOMAIN, cause, "bad");

        assertTrue(e instanceof AgentConfigMgtClientException);
        assertEquals(e.getErrorCode(), ErrorMessage.ERROR_CODE_INVALID_TENANT_DOMAIN.getCode());
        assertTrue(e.getMessage().contains("bad"));
    }

    @Test
    public void testParseConfig() {

        AgentConfig agentConfig = new AgentConfig();
        agentConfig.setAgentsExternallyManaged(true);

        ResourceAdd resourceAdd = Util.parseConfig(agentConfig);

        assertEquals(resourceAdd.getName(), AGENT_RESOURCE_NAME);
        assertEquals(resourceAdd.getAttributes().size(), 1);
        Attribute attribute = resourceAdd.getAttributes().get(0);
        assertEquals(attribute.getKey(), AGENTS_EXTERNALLY_MANAGED);
        assertEquals(attribute.getValue(), "true");
    }

    @Test
    public void testParseResourceWithAttributes() {

        Attribute attribute = new Attribute();
        attribute.setKey(AGENTS_EXTERNALLY_MANAGED);
        attribute.setValue("true");
        Resource resource = new Resource();
        resource.setHasAttribute(true);
        resource.setAttributes(Collections.singletonList(attribute));

        AgentConfig agentConfig = Util.parseResource(resource);

        assertTrue(agentConfig.isAgentsExternallyManaged());
    }

    @Test
    public void testParseResourceWithoutAttributes() {

        Resource resource = new Resource();
        resource.setHasAttribute(false);

        AgentConfig agentConfig = Util.parseResource(resource);

        assertFalse(agentConfig.isAgentsExternallyManaged());
    }

    @Test
    public void testParseResourceWithEmptyAttributeList() {

        Resource resource = new Resource();
        resource.setHasAttribute(true);
        resource.setAttributes(Collections.emptyList());

        AgentConfig agentConfig = Util.parseResource(resource);

        assertFalse(agentConfig.isAgentsExternallyManaged());
    }

    @Test
    public void testGetDefaultConfiguration() {

        AgentConfig agentConfig = Util.getDefaultConfiguration();

        assertFalse(agentConfig.isAgentsExternallyManaged());
    }
}
