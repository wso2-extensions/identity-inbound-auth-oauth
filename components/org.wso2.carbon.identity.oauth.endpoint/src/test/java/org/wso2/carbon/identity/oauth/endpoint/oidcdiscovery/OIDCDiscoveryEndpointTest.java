/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth.endpoint.oidcdiscovery;

import org.junit.Assert;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.discovery.DefaultOIDCProcessor;
import org.wso2.carbon.identity.discovery.OIDCDiscoveryEndPointException;
import org.wso2.carbon.identity.discovery.OIDProviderConfigResponse;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.endpoint.oidcdiscovery.impl.OIDProviderJSONResponseBuilder;
import org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.Response;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mockStatic;

/**
 * This class does unit test coverage for OIDCDiscoveryEndpoint class.
 */
@Listeners(MockitoTestNGListener.class)
public class OIDCDiscoveryEndpointTest {

    @Mock
    HttpServletRequest httpServletRequest;

    @Mock
    OIDProviderConfigResponse oidProviderConfigResponse;

    @Mock
    DefaultOIDCProcessor defaultOIDCProcessor;

    private OIDCDiscoveryEndpoint oidcDiscoveryEndpoint;
    private Object identityUtilObj;

    @BeforeClass
    public void setUp() throws Exception {

        oidcDiscoveryEndpoint = new OIDCDiscoveryEndpoint();
        Class<?> clazz = IdentityUtil.class;
        identityUtilObj = clazz.newInstance();
    }

    @DataProvider(name = "provideDataForGetOIDProviderConfigurationTokenEndpoint")
    public Object[][] provideDataGetOIDProviderConfigurationTokenEndpoint() {

        Map<String, Object> sampleConfigMap = getSampleConfigMap();
        return new Object[][]{
                {"token", sampleConfigMap, HttpServletResponse.SC_OK},
                {"oidcdiscovery", sampleConfigMap, HttpServletResponse.SC_OK},
                {"invalid_tokenEp", sampleConfigMap,
                        HttpServletResponse.SC_BAD_REQUEST},
        };
    }

    @Test(dataProvider = "provideDataForGetOIDProviderConfigurationTokenEndpoint")
    public void testGetOIDProviderConfigurationTokenEndpoint(
            String tokenEp, Map<String, Object> configMap, int expectedResponse)
            throws Exception {

        ThreadLocal<Map<String, Object>> threadLocalProperties = new ThreadLocal() {
            protected Map<String, Object> initialValue() {

                return new HashMap();
            }
        };

        threadLocalProperties.get().put(
                OAuthConstants.TENANT_NAME_FROM_CONTEXT, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);

        Field threadLocalPropertiesField = identityUtilObj.getClass().getDeclaredField("threadLocalProperties");

        Method getDeclaredFields0 = Class.class.getDeclaredMethod("getDeclaredFields0", boolean.class);
        getDeclaredFields0.setAccessible(true);
        Field[] fields = (Field[]) getDeclaredFields0.invoke(Field.class, false);
        Field modifiers = null;
        for (Field each : fields) {
            if ("modifiers".equals(each.getName())) {
                modifiers = each;
                break;
            }
        }
        modifiers.setAccessible(true);
        modifiers.setInt(threadLocalPropertiesField, threadLocalPropertiesField.getModifiers() & ~Modifier.FINAL);

        threadLocalPropertiesField.setAccessible(true);
        threadLocalPropertiesField.set(identityUtilObj, threadLocalProperties);

        try (MockedStatic<EndpointUtil> endpointUtil = mockStatic(EndpointUtil.class)) {
            endpointUtil.when(EndpointUtil::getOIDCService).thenReturn(defaultOIDCProcessor);
            lenient().when(defaultOIDCProcessor.getResponse(any(HttpServletRequest.class), any(String.class)))
                    .thenReturn(oidProviderConfigResponse);
            lenient().when(oidProviderConfigResponse.getConfigMap()).thenReturn(configMap);
            lenient().when(defaultOIDCProcessor.handleError(any(OIDCDiscoveryEndPointException.class)))
                    .thenReturn(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            oidcDiscoveryEndpoint.setOidProviderResponseBuilder(new OIDProviderJSONResponseBuilder());
            Response response = oidcDiscoveryEndpoint.getOIDProviderConfiguration(tokenEp, httpServletRequest);
            Assert.assertEquals(expectedResponse, response.getStatus());
            threadLocalProperties.get().remove(OAuthConstants.TENANT_NAME_FROM_CONTEXT);
        }
    }

    private Map<String, Object> getSampleConfigMap() {

        Map<String, Object> configMap = new HashMap<>();
        configMap.put("sampleStringKey", "sampleString");
        configMap.put("sampleStringArrayKey", new String[]{"sampleStringArrayElement1", "sampleStringArrayElement2"});
        return configMap;
    }
}
