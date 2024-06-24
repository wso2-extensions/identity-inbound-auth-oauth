/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.discovery.internal;

import org.mockito.Mock;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.identity.discovery.DefaultOIDCProcessor;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.testng.Assert.assertEquals;

/**
 * Unit test covering OIDCDiscoveryServiceComponent class.
 */
public class OIDCDiscoveryServiceComponentTest {

    @Mock
    BundleContext bundleContext;

    @Mock
    private ComponentContext context;

    @Mock
    ClaimMetadataManagementService claimMetadataManagementService;

    @BeforeClass
    public void setUp() throws Exception {

        initMocks(this);
    }

    @Test
    public void testGetBundleContext() throws Exception {

        OIDCDiscoveryServiceComponent.getBundleContext();
        assertEquals(OIDCDiscoveryServiceComponent.getBundleContext(), bundleContext);
    }

    @Test
    public void testActivate() throws Exception {

        when(context.getBundleContext()).thenReturn(this.bundleContext);

        final String[] serviceName = new String[1];

        doAnswer(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {

                DefaultOIDCProcessor defaultOIDCProcessor = (DefaultOIDCProcessor) invocation.getArguments()[1];
                serviceName[0] = defaultOIDCProcessor.getClass().getName();
                return null;
            }
        }).when(this.bundleContext).registerService(anyString(), any(DefaultOIDCProcessor.class),
                isNull());

        OIDCDiscoveryServiceComponent oidcDiscoveryServiceComponent = new OIDCDiscoveryServiceComponent();
        oidcDiscoveryServiceComponent.activate(context);

        assertEquals(DefaultOIDCProcessor.class.getName(), serviceName[0], "error");
    }

    @Test
    public void testSetClaimManagementService() throws Exception {

        OIDCDiscoveryServiceComponent oidcDiscoveryServiceComponent = new OIDCDiscoveryServiceComponent();
        oidcDiscoveryServiceComponent.setClaimManagementService(claimMetadataManagementService);
    }

    @Test
    public void testUnsetClaimManagementService() throws Exception {

        OIDCDiscoveryServiceComponent oidcDiscoveryServiceComponent = new OIDCDiscoveryServiceComponent();
        oidcDiscoveryServiceComponent.unsetClaimManagementService(null);
    }
}
