/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth.endpoint.authzservermetadata;

import org.junit.Assert;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.testng.MockitoTestNGListener;
import org.osgi.framework.BundleContext;
import org.osgi.util.tracker.ServiceTracker;
import org.testng.annotations.*;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.context.internal.OSGiDataHolder;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.discovery.DefaultOIDCProcessor;
import org.wso2.carbon.identity.discovery.OIDCDiscoveryEndPointException;
import org.wso2.carbon.identity.discovery.OIDCProcessor;
import org.wso2.carbon.identity.discovery.OIDProviderConfigResponse;
import org.wso2.carbon.identity.discovery.builders.OIDProviderResponseBuilder;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.endpoint.oidcdiscovery.OIDCDiscoveryServiceFactory;
import org.wso2.carbon.identity.oauth.endpoint.util.factory.OIDCProviderServiceFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.Response;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.lenient;

/**
 * This class tests the OAuth 2.0 Authorization Server Metadata Endpoint functionality
 */
@WithCarbonHome
@Listeners(MockitoTestNGListener.class)
public class AuthzServerMetadataEndpointTest {

    @Mock
    HttpServletRequest httpServletRequest;

    @Mock
    OIDProviderConfigResponse oidProviderConfigResponse;

    @Mock
    DefaultOIDCProcessor defaultOIDCProcessor;

    @Mock
    OIDProviderResponseBuilder oidProviderResponseBuilder;

    @Mock
    BundleContext bundleContext;

    MockedConstruction<ServiceTracker> mockedConstruction;

    private AuthzServerMetadataEndpoint authzServerMetadataEndpoint;
    private Object identityUtilObj;

    @BeforeClass
    public void setUp() throws Exception {

        authzServerMetadataEndpoint = new AuthzServerMetadataEndpoint();
        Class<?> clazz = IdentityUtil.class;
        identityUtilObj = clazz.newInstance();
    }

    @BeforeMethod
    public void setUpMethod() {

        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain("carbon.super");

        ArgumentCaptor<String> argumentCaptor = ArgumentCaptor.forClass(String.class);
        mockedConstruction = mockConstruction(ServiceTracker.class,
                (mock, context) -> {
                    verify(bundleContext, atLeastOnce()).createFilter(argumentCaptor.capture());
                    if (argumentCaptor.getValue().contains(OIDProviderResponseBuilder.class.getName())) {
                        when(mock.getServices()).thenReturn(new Object[]{oidProviderResponseBuilder});
                    }
                    if (argumentCaptor.getValue().contains(OIDCProcessor.class.getName())) {
                        when(mock.getServices()).thenReturn(new Object[]{defaultOIDCProcessor});
                    }
                });
        OSGiDataHolder.getInstance().setBundleContext(bundleContext);
    }

    @AfterMethod
    public void tearDown() {

        mockedConstruction.close();
        PrivilegedCarbonContext.endTenantFlow();
    }

    @Test(dataProvider = "provideDataForGetOAuthAuthzServerMetadataEndpoint")
    public void testGetOAuthAuthzServerMetadataEndpoint(Map<String, Object> configMap, int expectedResponse)
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

        try (MockedStatic<OIDCProviderServiceFactory> oidcProviderServiceFactory =
                     mockStatic(OIDCProviderServiceFactory.class);
             MockedStatic<OIDCDiscoveryServiceFactory> oidcDiscoveryServiceFactory =
                     mockStatic(OIDCDiscoveryServiceFactory.class)) {

            oidcDiscoveryServiceFactory.when(OIDCDiscoveryServiceFactory::getOIDProviderResponseBuilder)
                    .thenReturn(oidProviderResponseBuilder);
            oidcProviderServiceFactory.when(OIDCProviderServiceFactory::getOIDCService)
                    .thenReturn(defaultOIDCProcessor);
            lenient().when(defaultOIDCProcessor.getResponse(any(), any())).thenReturn(oidProviderConfigResponse);
            lenient().when(oidProviderConfigResponse.getConfigMap()).thenReturn(configMap);
            lenient().when(defaultOIDCProcessor.handleError(any(OIDCDiscoveryEndPointException.class)))
                    .thenReturn(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            Response response = authzServerMetadataEndpoint.getAuthzServerMetadata(httpServletRequest);
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
