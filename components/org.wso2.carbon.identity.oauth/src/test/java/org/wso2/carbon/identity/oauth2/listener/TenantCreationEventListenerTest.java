/*
* Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
package org.wso2.carbon.identity.oauth2.listener;

import org.mockito.Mock;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.TestConstants;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;
import org.wso2.carbon.registry.core.Resource;
import org.wso2.carbon.registry.core.ResourceImpl;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.registry.core.session.UserRegistry;
import org.wso2.carbon.stratos.common.beans.TenantInfoBean;

import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class TenantCreationEventListenerTest extends PowerMockIdentityBaseTest {

    private TenantCreationEventListener tenantCreationEventListener = new TenantCreationEventListener();

    @Mock
    RegistryService registryService;

    @Mock
    UserRegistry registry;

    @Mock
    IdentityConfigParser identityConfigParser;

    @BeforeMethod
    public void setUp() throws Exception {
        String carbonHome = getClass().getResource("/").getFile();
        System.setProperty(CarbonBaseConstants.CARBON_HOME, carbonHome);
        System.setProperty(TestConstants.CARBON_PROTOCOL, TestConstants.CARBON_PROTOCOL_HTTPS);
        System.setProperty(TestConstants.CARBON_HOST, TestConstants.CARBON_HOST_LOCALHOST);
        System.setProperty(TestConstants.CARBON_MANAGEMENT_PORT, TestConstants.CARBON_DEFAULT_HTTPS_PORT);
        OAuth2ServiceComponentHolder.setRegistryService(registryService);
    }

    @Test
    public void testOnTenantCreate() throws Exception {
        when(OAuth2ServiceComponentHolder.getRegistryService()
                                         .getConfigSystemRegistry(TestConstants.TENANT_ID)).thenReturn(registry);
        Resource resource = new ResourceImpl();
        when(registry.newResource()).thenReturn(resource);
        TenantInfoBean tenantInfoBean = new TenantInfoBean();
        tenantInfoBean.setTenantId(TestConstants.TENANT_ID);
        tenantCreationEventListener.onTenantCreate(tenantInfoBean);
        verify(registry, times(1)).put(OAuthConstants.SCOPE_RESOURCE_PATH, resource);
    }

    @Test
    public void testGetListenerOrder() {
        int listenerOrder = tenantCreationEventListener.getListenerOrder();
        Assert.assertEquals(listenerOrder, 0, "Listener order is different from expected.");
    }

}
