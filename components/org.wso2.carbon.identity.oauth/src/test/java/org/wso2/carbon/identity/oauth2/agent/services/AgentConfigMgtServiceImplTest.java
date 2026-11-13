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

import org.mockito.MockedStatic;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.configuration.mgt.core.ConfigurationManager;
import org.wso2.carbon.identity.configuration.mgt.core.exception.ConfigurationManagementException;
import org.wso2.carbon.identity.configuration.mgt.core.model.Attribute;
import org.wso2.carbon.identity.configuration.mgt.core.model.Resource;
import org.wso2.carbon.identity.configuration.mgt.core.model.ResourceAdd;
import org.wso2.carbon.identity.configuration.mgt.core.model.ResourceTypeAdd;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth2.agent.cache.AgentConfigCache;
import org.wso2.carbon.identity.oauth2.agent.cache.AgentConfigCacheEntry;
import org.wso2.carbon.identity.oauth2.agent.cache.AgentConfigCacheKey;
import org.wso2.carbon.identity.oauth2.agent.exceptions.AgentConfigMgtClientException;
import org.wso2.carbon.identity.oauth2.agent.exceptions.AgentConfigMgtException;
import org.wso2.carbon.identity.oauth2.agent.exceptions.AgentConfigMgtServerException;
import org.wso2.carbon.identity.oauth2.agent.models.AgentConfig;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;

import java.util.Collections;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;
import static org.wso2.carbon.identity.configuration.mgt.core.constant.ConfigurationConstants.ErrorMessages.ERROR_CODE_RESOURCE_DOES_NOT_EXISTS;
import static org.wso2.carbon.identity.configuration.mgt.core.constant.ConfigurationConstants.ErrorMessages.ERROR_CODE_RESOURCE_TYPE_ALREADY_EXISTS;
import static org.wso2.carbon.identity.configuration.mgt.core.constant.ConfigurationConstants.ErrorMessages.ERROR_CODE_RESOURCE_TYPE_DOES_NOT_EXISTS;
import static org.wso2.carbon.identity.oauth2.agent.utils.Constants.AGENTS_EXTERNALLY_MANAGED;
import static org.wso2.carbon.identity.oauth2.agent.utils.Constants.AGENT_RESOURCE_NAME;
import static org.wso2.carbon.identity.oauth2.agent.utils.Constants.AGENT_RESOURCE_TYPE_NAME;

/**
 * Unit tests for {@link AgentConfigMgtServiceImpl}.
 */
public class AgentConfigMgtServiceImplTest {

    private static final String TENANT_DOMAIN = "carbon.super";

    private final AgentConfigMgtServiceImpl service = new AgentConfigMgtServiceImpl();

    @Test
    public void testGetAgentConfigServedFromCache() throws Exception {

        AgentConfig cached = new AgentConfig();
        cached.setAgentsExternallyManaged(true);

        try (MockedStatic<AgentConfigCache> cacheStatic = mockStatic(AgentConfigCache.class)) {
            AgentConfigCache cache = mock(AgentConfigCache.class);
            cacheStatic.when(AgentConfigCache::getInstance).thenReturn(cache);
            when(cache.getValueFromCache(any(AgentConfigCacheKey.class), eq(TENANT_DOMAIN)))
                    .thenReturn(new AgentConfigCacheEntry(cached));

            AgentConfig result = service.getAgentConfig(TENANT_DOMAIN);

            assertNotNull(result);
            assertTrue(result.isAgentsExternallyManaged());
        }
    }

    @Test
    public void testGetAgentConfigFromExistingResource() throws Exception {

        Attribute attribute = new Attribute();
        attribute.setKey(AGENTS_EXTERNALLY_MANAGED);
        attribute.setValue("true");
        Resource resource = new Resource();
        resource.setHasAttribute(true);
        resource.setAttributes(Collections.singletonList(attribute));

        try (MockedStatic<AgentConfigCache> cacheStatic = mockStatic(AgentConfigCache.class);
             MockedStatic<OAuth2ServiceComponentHolder> holderStatic =
                     mockStatic(OAuth2ServiceComponentHolder.class)) {

            AgentConfigCache cache = mock(AgentConfigCache.class);
            cacheStatic.when(AgentConfigCache::getInstance).thenReturn(cache);
            when(cache.getValueFromCache(any(AgentConfigCacheKey.class), eq(TENANT_DOMAIN))).thenReturn(null);

            ConfigurationManager configurationManager = mock(ConfigurationManager.class);
            mockHolder(holderStatic, configurationManager);
            when(configurationManager.getResource(AGENT_RESOURCE_TYPE_NAME, AGENT_RESOURCE_NAME, true))
                    .thenReturn(resource);

            AgentConfig result = service.getAgentConfig(TENANT_DOMAIN);

            assertTrue(result.isAgentsExternallyManaged());
            verify(cache).addToCacheOnRead(any(AgentConfigCacheKey.class), any(AgentConfigCacheEntry.class),
                    eq(TENANT_DOMAIN));
        }
    }

    @Test
    public void testGetAgentConfigReturnsDefaultWhenResourceMissing() throws Exception {

        try (MockedStatic<AgentConfigCache> cacheStatic = mockStatic(AgentConfigCache.class);
             MockedStatic<OAuth2ServiceComponentHolder> holderStatic =
                     mockStatic(OAuth2ServiceComponentHolder.class)) {

            AgentConfigCache cache = mock(AgentConfigCache.class);
            cacheStatic.when(AgentConfigCache::getInstance).thenReturn(cache);
            when(cache.getValueFromCache(any(AgentConfigCacheKey.class), eq(TENANT_DOMAIN))).thenReturn(null);

            ConfigurationManager configurationManager = mock(ConfigurationManager.class);
            mockHolder(holderStatic, configurationManager);
            // A "resource does not exist" error maps to the default configuration.
            when(configurationManager.getResource(AGENT_RESOURCE_TYPE_NAME, AGENT_RESOURCE_NAME, true))
                    .thenThrow(new ConfigurationManagementException("not found",
                            ERROR_CODE_RESOURCE_DOES_NOT_EXISTS.getCode()));

            AgentConfig result = service.getAgentConfig(TENANT_DOMAIN);

            assertNotNull(result);
            assertFalse(result.isAgentsExternallyManaged());
        }
    }

    @Test
    public void testGetAgentConfigWrapsConfigMgtException() throws Exception {

        try (MockedStatic<AgentConfigCache> cacheStatic = mockStatic(AgentConfigCache.class);
             MockedStatic<OAuth2ServiceComponentHolder> holderStatic =
                     mockStatic(OAuth2ServiceComponentHolder.class)) {

            AgentConfigCache cache = mock(AgentConfigCache.class);
            cacheStatic.when(AgentConfigCache::getInstance).thenReturn(cache);
            when(cache.getValueFromCache(any(AgentConfigCacheKey.class), eq(TENANT_DOMAIN))).thenReturn(null);

            ConfigurationManager configurationManager = mock(ConfigurationManager.class);
            mockHolder(holderStatic, configurationManager);
            when(configurationManager.getResource(AGENT_RESOURCE_TYPE_NAME, AGENT_RESOURCE_NAME, true))
                    .thenThrow(new ConfigurationManagementException("boom", "OTHER-ERROR"));

            service.getAgentConfig(TENANT_DOMAIN);
            fail("Expected AgentConfigMgtServerException.");
        } catch (AgentConfigMgtException e) {
            assertTrue(e instanceof AgentConfigMgtServerException);
        }
    }

    @Test
    public void testSetAgentConfig() throws Exception {

        AgentConfig agentConfig = new AgentConfig();
        agentConfig.setAgentsExternallyManaged(true);

        try (MockedStatic<IdentityTenantUtil> tenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<AgentConfigCache> cacheStatic = mockStatic(AgentConfigCache.class);
             MockedStatic<OAuth2ServiceComponentHolder> holderStatic =
                     mockStatic(OAuth2ServiceComponentHolder.class)) {

            tenantUtil.when(() -> IdentityTenantUtil.getTenantId(TENANT_DOMAIN)).thenReturn(-1234);
            AgentConfigCache cache = mock(AgentConfigCache.class);
            cacheStatic.when(AgentConfigCache::getInstance).thenReturn(cache);
            ConfigurationManager configurationManager = mock(ConfigurationManager.class);
            mockHolder(holderStatic, configurationManager);

            service.setAgentConfig(agentConfig, TENANT_DOMAIN);

            verify(configurationManager).replaceResource(eq(AGENT_RESOURCE_TYPE_NAME), any(ResourceAdd.class));
            verify(cache).clearCacheEntry(any(AgentConfigCacheKey.class), eq(TENANT_DOMAIN));
        }
    }

    @Test
    public void testSetAgentConfigInvalidTenant() {

        try (MockedStatic<IdentityTenantUtil> tenantUtil = mockStatic(IdentityTenantUtil.class)) {
            tenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString()))
                    .thenThrow(IdentityRuntimeException.error("invalid"));

            service.setAgentConfig(new AgentConfig(), "invalid-tenant");
            fail("Expected AgentConfigMgtClientException.");
        } catch (AgentConfigMgtException e) {
            assertTrue(e instanceof AgentConfigMgtClientException);
        }
    }

    @Test
    public void testSetAgentConfigWrapsConfigMgtException() throws Exception {

        try (MockedStatic<IdentityTenantUtil> tenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<AgentConfigCache> cacheStatic = mockStatic(AgentConfigCache.class);
             MockedStatic<OAuth2ServiceComponentHolder> holderStatic =
                     mockStatic(OAuth2ServiceComponentHolder.class)) {

            tenantUtil.when(() -> IdentityTenantUtil.getTenantId(TENANT_DOMAIN)).thenReturn(-1234);
            cacheStatic.when(AgentConfigCache::getInstance).thenReturn(mock(AgentConfigCache.class));
            ConfigurationManager configurationManager = mock(ConfigurationManager.class);
            mockHolder(holderStatic, configurationManager);
            when(configurationManager.replaceResource(anyString(), any(ResourceAdd.class)))
                    .thenThrow(new ConfigurationManagementException("boom", "ERROR"));

            service.setAgentConfig(new AgentConfig(), TENANT_DOMAIN);
            fail("Expected AgentConfigMgtServerException.");
        } catch (AgentConfigMgtException e) {
            assertTrue(e instanceof AgentConfigMgtServerException);
        }
    }

    @Test
    public void testSetAgentConfigCreatesResourceTypeOnDemand() throws Exception {

        try (MockedStatic<IdentityTenantUtil> tenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<AgentConfigCache> cacheStatic = mockStatic(AgentConfigCache.class);
             MockedStatic<OAuth2ServiceComponentHolder> holderStatic =
                     mockStatic(OAuth2ServiceComponentHolder.class)) {

            tenantUtil.when(() -> IdentityTenantUtil.getTenantId(TENANT_DOMAIN)).thenReturn(-1234);
            AgentConfigCache cache = mock(AgentConfigCache.class);
            cacheStatic.when(AgentConfigCache::getInstance).thenReturn(cache);
            ConfigurationManager configurationManager = mock(ConfigurationManager.class);
            mockHolder(holderStatic, configurationManager);
            // The first write fails because the resource type is not registered; the retry succeeds.
            when(configurationManager.replaceResource(eq(AGENT_RESOURCE_TYPE_NAME), any(ResourceAdd.class)))
                    .thenThrow(new ConfigurationManagementException("no type",
                            ERROR_CODE_RESOURCE_TYPE_DOES_NOT_EXISTS.getCode()))
                    .thenReturn(new Resource());

            service.setAgentConfig(new AgentConfig(), TENANT_DOMAIN);

            verify(configurationManager).addResourceType(any(ResourceTypeAdd.class));
            verify(configurationManager, times(2))
                    .replaceResource(eq(AGENT_RESOURCE_TYPE_NAME), any(ResourceAdd.class));
            verify(cache).clearCacheEntry(any(AgentConfigCacheKey.class), eq(TENANT_DOMAIN));
        }
    }

    @Test
    public void testSetAgentConfigWhenResourceTypeCreatedConcurrently() throws Exception {

        try (MockedStatic<IdentityTenantUtil> tenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<AgentConfigCache> cacheStatic = mockStatic(AgentConfigCache.class);
             MockedStatic<OAuth2ServiceComponentHolder> holderStatic =
                     mockStatic(OAuth2ServiceComponentHolder.class)) {

            tenantUtil.when(() -> IdentityTenantUtil.getTenantId(TENANT_DOMAIN)).thenReturn(-1234);
            AgentConfigCache cache = mock(AgentConfigCache.class);
            cacheStatic.when(AgentConfigCache::getInstance).thenReturn(cache);
            ConfigurationManager configurationManager = mock(ConfigurationManager.class);
            mockHolder(holderStatic, configurationManager);
            when(configurationManager.replaceResource(eq(AGENT_RESOURCE_TYPE_NAME), any(ResourceAdd.class)))
                    .thenThrow(new ConfigurationManagementException("no type",
                            ERROR_CODE_RESOURCE_TYPE_DOES_NOT_EXISTS.getCode()))
                    .thenReturn(new Resource());
            // A concurrent writer already created the type; this is treated as success.
            when(configurationManager.addResourceType(any(ResourceTypeAdd.class)))
                    .thenThrow(new ConfigurationManagementException("exists",
                            ERROR_CODE_RESOURCE_TYPE_ALREADY_EXISTS.getCode()));

            service.setAgentConfig(new AgentConfig(), TENANT_DOMAIN);

            verify(configurationManager, times(2))
                    .replaceResource(eq(AGENT_RESOURCE_TYPE_NAME), any(ResourceAdd.class));
            verify(cache).clearCacheEntry(any(AgentConfigCacheKey.class), eq(TENANT_DOMAIN));
        }
    }

    @Test
    public void testSetAgentConfigWrapsResourceTypeCreationFailure() throws Exception {

        try (MockedStatic<IdentityTenantUtil> tenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<AgentConfigCache> cacheStatic = mockStatic(AgentConfigCache.class);
             MockedStatic<OAuth2ServiceComponentHolder> holderStatic =
                     mockStatic(OAuth2ServiceComponentHolder.class)) {

            tenantUtil.when(() -> IdentityTenantUtil.getTenantId(TENANT_DOMAIN)).thenReturn(-1234);
            cacheStatic.when(AgentConfigCache::getInstance).thenReturn(mock(AgentConfigCache.class));
            ConfigurationManager configurationManager = mock(ConfigurationManager.class);
            mockHolder(holderStatic, configurationManager);
            when(configurationManager.replaceResource(eq(AGENT_RESOURCE_TYPE_NAME), any(ResourceAdd.class)))
                    .thenThrow(new ConfigurationManagementException("no type",
                            ERROR_CODE_RESOURCE_TYPE_DOES_NOT_EXISTS.getCode()));
            // Resource type creation fails for a reason other than "already exists" and must propagate.
            when(configurationManager.addResourceType(any(ResourceTypeAdd.class)))
                    .thenThrow(new ConfigurationManagementException("boom", "OTHER-ERROR"));

            service.setAgentConfig(new AgentConfig(), TENANT_DOMAIN);
            fail("Expected AgentConfigMgtServerException.");
        } catch (AgentConfigMgtException e) {
            assertTrue(e instanceof AgentConfigMgtServerException);
        }
    }

    @Test
    public void testGetAgentConfigReturnsDefaultWhenResourceTypeMissing() throws Exception {

        try (MockedStatic<AgentConfigCache> cacheStatic = mockStatic(AgentConfigCache.class);
             MockedStatic<OAuth2ServiceComponentHolder> holderStatic =
                     mockStatic(OAuth2ServiceComponentHolder.class)) {

            AgentConfigCache cache = mock(AgentConfigCache.class);
            cacheStatic.when(AgentConfigCache::getInstance).thenReturn(cache);
            when(cache.getValueFromCache(any(AgentConfigCacheKey.class), eq(TENANT_DOMAIN))).thenReturn(null);

            ConfigurationManager configurationManager = mock(ConfigurationManager.class);
            mockHolder(holderStatic, configurationManager);
            // A "resource type does not exist" error also maps to the default configuration.
            when(configurationManager.getResource(AGENT_RESOURCE_TYPE_NAME, AGENT_RESOURCE_NAME, true))
                    .thenThrow(new ConfigurationManagementException("no type",
                            ERROR_CODE_RESOURCE_TYPE_DOES_NOT_EXISTS.getCode()));

            AgentConfig result = service.getAgentConfig(TENANT_DOMAIN);

            assertNotNull(result);
            assertFalse(result.isAgentsExternallyManaged());
        }
    }

    @Test
    public void testDeleteAgentConfigWhenResourceExists() throws Exception {

        try (MockedStatic<IdentityTenantUtil> tenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<AgentConfigCache> cacheStatic = mockStatic(AgentConfigCache.class);
             MockedStatic<OAuth2ServiceComponentHolder> holderStatic =
                     mockStatic(OAuth2ServiceComponentHolder.class)) {

            tenantUtil.when(() -> IdentityTenantUtil.getTenantId(TENANT_DOMAIN)).thenReturn(-1234);
            AgentConfigCache cache = mock(AgentConfigCache.class);
            cacheStatic.when(AgentConfigCache::getInstance).thenReturn(cache);
            ConfigurationManager configurationManager = mock(ConfigurationManager.class);
            mockHolder(holderStatic, configurationManager);
            when(configurationManager.getResource(AGENT_RESOURCE_TYPE_NAME, AGENT_RESOURCE_NAME, true))
                    .thenReturn(new Resource());

            service.deleteAgentConfig(TENANT_DOMAIN);

            verify(configurationManager).deleteResource(AGENT_RESOURCE_TYPE_NAME, AGENT_RESOURCE_NAME);
            verify(cache).clearCacheEntry(any(AgentConfigCacheKey.class), eq(TENANT_DOMAIN));
        }
    }

    @Test
    public void testDeleteAgentConfigWhenResourceMissing() throws Exception {

        try (MockedStatic<IdentityTenantUtil> tenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<AgentConfigCache> cacheStatic = mockStatic(AgentConfigCache.class);
             MockedStatic<OAuth2ServiceComponentHolder> holderStatic =
                     mockStatic(OAuth2ServiceComponentHolder.class)) {

            tenantUtil.when(() -> IdentityTenantUtil.getTenantId(TENANT_DOMAIN)).thenReturn(-1234);
            AgentConfigCache cache = mock(AgentConfigCache.class);
            cacheStatic.when(AgentConfigCache::getInstance).thenReturn(cache);
            ConfigurationManager configurationManager = mock(ConfigurationManager.class);
            mockHolder(holderStatic, configurationManager);
            when(configurationManager.getResource(AGENT_RESOURCE_TYPE_NAME, AGENT_RESOURCE_NAME, true))
                    .thenReturn(null);

            service.deleteAgentConfig(TENANT_DOMAIN);

            verify(configurationManager, times(0)).deleteResource(anyString(), anyString());
            verify(cache, times(0)).clearCacheEntry(any(AgentConfigCacheKey.class), anyString());
        }
    }

    @Test
    public void testDeleteAgentConfigInvalidTenant() {

        try (MockedStatic<IdentityTenantUtil> tenantUtil = mockStatic(IdentityTenantUtil.class)) {
            tenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString()))
                    .thenThrow(IdentityRuntimeException.error("invalid"));

            service.deleteAgentConfig("invalid-tenant");
            fail("Expected AgentConfigMgtClientException.");
        } catch (AgentConfigMgtException e) {
            assertTrue(e instanceof AgentConfigMgtClientException);
        }
    }

    @Test
    public void testGetAgentConfigReturnsDefaultWhenConfigurationManagerUnavailable() throws Exception {

        try (MockedStatic<AgentConfigCache> cacheStatic = mockStatic(AgentConfigCache.class);
             MockedStatic<OAuth2ServiceComponentHolder> holderStatic =
                     mockStatic(OAuth2ServiceComponentHolder.class)) {

            AgentConfigCache cache = mock(AgentConfigCache.class);
            cacheStatic.when(AgentConfigCache::getInstance).thenReturn(cache);
            when(cache.getValueFromCache(any(AgentConfigCacheKey.class), eq(TENANT_DOMAIN))).thenReturn(null);
            // ConfigurationManager not set in the holder.
            mockHolder(holderStatic, null);

            AgentConfig result = service.getAgentConfig(TENANT_DOMAIN);

            assertNotNull(result);
            assertFalse(result.isAgentsExternallyManaged());
        }
    }

    private void mockHolder(MockedStatic<OAuth2ServiceComponentHolder> holderStatic,
                            ConfigurationManager configurationManager) {

        OAuth2ServiceComponentHolder holder = mock(OAuth2ServiceComponentHolder.class);
        holderStatic.when(OAuth2ServiceComponentHolder::getInstance).thenReturn(holder);
        when(holder.getConfigurationManager()).thenReturn(configurationManager);
    }
}
