/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.discovery;

import org.mockito.MockedStatic;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.testng.Assert.assertEquals;
import static org.wso2.carbon.identity.discovery.DiscoveryUtil.OIDC_USE_ENTITY_ID_AS_ISSUER_IN_DISCOVERY;

/**
 * Unit tests.
 */
public class DiscoveryUtilTest {

    @BeforeMethod
    public void setUp() {
        initMocks(this);
    }

    @Test
    public void testIsUseEntityIdAsIssuerInOidcDiscovery() {

        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {
            identityUtil.when(() -> IdentityUtil.getProperty(eq(OIDC_USE_ENTITY_ID_AS_ISSUER_IN_DISCOVERY)))
                    .thenReturn(null);
            assertEquals(DiscoveryUtil.isUseEntityIdAsIssuerInOidcDiscovery(), true);
        }
    }

    @Test
    public void testIsUseEntityIdAsIssuerInOidcDiscovery1() {

        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {
            identityUtil.when(() -> IdentityUtil.getProperty(eq(OIDC_USE_ENTITY_ID_AS_ISSUER_IN_DISCOVERY)))
                    .thenReturn(Boolean.FALSE.toString());
            assertEquals(DiscoveryUtil.isUseEntityIdAsIssuerInOidcDiscovery(), false);
        }
    }
}
