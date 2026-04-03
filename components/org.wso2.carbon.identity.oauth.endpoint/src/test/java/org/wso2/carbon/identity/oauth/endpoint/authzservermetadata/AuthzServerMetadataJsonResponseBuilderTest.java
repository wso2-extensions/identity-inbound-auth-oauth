/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.endpoint.authzservermetadata;

import org.mockito.Mock;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.Assert;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.discovery.OIDProviderConfigResponse;

import java.util.HashMap;
import java.util.Map;

import static org.mockito.Mockito.when;

/**
 * Tests for AuthzServerMetadataJsonResponseBuilder.
 */
@Listeners(MockitoTestNGListener.class)
public class AuthzServerMetadataJsonResponseBuilderTest {

    @Mock
    OIDProviderConfigResponse oidProviderConfigResponse;

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testGetConfigStringWithNullResponseThrows() {

        AuthzServerMetadataJsonResponseBuilder.getAuthzServerMetadataConfigString(null);
    }

    @Test
    public void testGetConfigStringFiltersIdTokenFromResponseTypes() {

        Map<String, Object> configMap = new HashMap<>();
        configMap.put("response_types_supported",
                new String[]{"code", "token", "id_token", "code id_token"});
        when(oidProviderConfigResponse.getConfigMap()).thenReturn(configMap);

        String result = AuthzServerMetadataJsonResponseBuilder
                .getAuthzServerMetadataConfigString(oidProviderConfigResponse);

        Assert.assertNotNull(result);
        Assert.assertTrue(result.contains("\"code\""));
        Assert.assertTrue(result.contains("\"token\""));
        Assert.assertFalse(result.contains("id_token"));
    }

    @Test
    public void testGetConfigStringWithEmptyConfigMap() {

        when(oidProviderConfigResponse.getConfigMap()).thenReturn(new HashMap<>());

        String result = AuthzServerMetadataJsonResponseBuilder
                .getAuthzServerMetadataConfigString(oidProviderConfigResponse);

        Assert.assertNotNull(result);
    }
}
