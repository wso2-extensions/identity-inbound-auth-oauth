/*
 * Copyright (c) 2026, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.rar.core;

import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.api.resource.mgt.APIResourceMgtException;
import org.wso2.carbon.identity.api.resource.mgt.AuthorizationDetailsTypeManager;
import org.wso2.carbon.identity.application.common.model.AuthorizationDetailsType;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;

import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.Optional;
import java.util.Set;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.wso2.carbon.identity.oauth2.TestConstants.TENANT_DOMAIN;
import static org.wso2.carbon.identity.oauth2.TestConstants.TEST_TYPE;

/**
 * Test class for {@link AuthorizationDetailsProcessorFactory}.
 */
@WithCarbonHome
public class AuthorizationDetailsProcessorFactoryTest {

    private AuthorizationDetailsProcessorFactory factory;
    private MockedStatic<CarbonContext> carbonContextMockedStatic;
    private MockedStatic<OAuth2ServiceComponentHolder> holderMockedStatic;
    private OAuth2ServiceComponentHolder holderMock;
    private AuthorizationDetailsTypeManager typeManagerMock;

    @BeforeMethod
    public void setUp() throws Exception {

        // Reset singleton instance to ensure test isolation.
        Field instanceField = AuthorizationDetailsProcessorFactory.class.getDeclaredField("instance");
        instanceField.setAccessible(true);
        instanceField.set(null, null);

        factory = AuthorizationDetailsProcessorFactory.getInstance();

        // Mock CarbonContext.
        CarbonContext carbonContextMock = mock(CarbonContext.class);
        when(carbonContextMock.getTenantDomain()).thenReturn(TENANT_DOMAIN);

        carbonContextMockedStatic = Mockito.mockStatic(CarbonContext.class);
        carbonContextMockedStatic.when(CarbonContext::getThreadLocalCarbonContext).thenReturn(carbonContextMock);

        // Mock OAuth2ServiceComponentHolder and AuthorizationDetailsTypeManager.
        typeManagerMock = mock(AuthorizationDetailsTypeManager.class);
        holderMock = mock(OAuth2ServiceComponentHolder.class);
        when(holderMock.getAuthorizationDetailsTypeManager()).thenReturn(typeManagerMock);

        holderMockedStatic = Mockito.mockStatic(OAuth2ServiceComponentHolder.class);
        holderMockedStatic.when(OAuth2ServiceComponentHolder::getInstance).thenReturn(holderMock);
    }

    @AfterMethod
    public void tearDown() throws Exception {

        if (carbonContextMockedStatic != null && !carbonContextMockedStatic.isClosed()) {
            carbonContextMockedStatic.close();
        }
        if (holderMockedStatic != null && !holderMockedStatic.isClosed()) {
            holderMockedStatic.close();
        }

        // Reset singleton instance after each test.
        Field instanceField = AuthorizationDetailsProcessorFactory.class.getDeclaredField("instance");
        instanceField.setAccessible(true);
        instanceField.set(null, null);
    }

    // ---- getInstance() ----

    @Test
    public void shouldReturnNonNullSingletonInstance() {

        assertNotNull(AuthorizationDetailsProcessorFactory.getInstance());
    }

    @Test
    public void shouldReturnSameInstanceOnMultipleCalls() {

        AuthorizationDetailsProcessorFactory first = AuthorizationDetailsProcessorFactory.getInstance();
        AuthorizationDetailsProcessorFactory second = AuthorizationDetailsProcessorFactory.getInstance();
        assertEquals(first, second, "getInstance() should return the same singleton instance.");
    }

    // ---- getAuthorizationDetailsProcessorByType() ----

    @Test
    public void shouldReturnEmptyOptionalForUnregisteredType() {

        Optional<AuthorizationDetailsProcessor> result =
                factory.getAuthorizationDetailsProcessorByType("unregistered_type");
        assertFalse(result.isPresent(), "Should return empty Optional for unregistered type.");
    }

    @Test
    public void shouldReturnProcessorAfterRegistration() {

        AuthorizationDetailsProcessor processorMock = mock(AuthorizationDetailsProcessor.class);
        when(processorMock.getType()).thenReturn(TEST_TYPE);

        factory.setAuthorizationDetailsProcessors(processorMock);

        Optional<AuthorizationDetailsProcessor> result =
                factory.getAuthorizationDetailsProcessorByType(TEST_TYPE);
        assertTrue(result.isPresent(), "Should return processor for registered type.");
        assertEquals(result.get(), processorMock);
    }

    // ---- setAuthorizationDetailsProcessors() ----

    @Test
    public void shouldIgnoreNullProcessor() {

        factory.setAuthorizationDetailsProcessors(null);
        assertFalse(factory.getAuthorizationDetailsProcessorByType(TEST_TYPE).isPresent(),
                "Null processor should not be registered.");
    }

    @Test
    public void shouldIgnoreProcessorWithNullType() {

        AuthorizationDetailsProcessor processorMock = mock(AuthorizationDetailsProcessor.class);
        when(processorMock.getType()).thenReturn(null);

        factory.setAuthorizationDetailsProcessors(processorMock);
        assertFalse(factory.getAuthorizationDetailsProcessorByType(null).isPresent(),
                "Processor with null type should not be registered.");
    }

    @Test
    public void shouldIgnoreProcessorWithBlankType() {

        AuthorizationDetailsProcessor processorMock = mock(AuthorizationDetailsProcessor.class);
        when(processorMock.getType()).thenReturn("   ");

        factory.setAuthorizationDetailsProcessors(processorMock);
        assertFalse(factory.getAuthorizationDetailsProcessorByType("   ").isPresent(),
                "Processor with blank type should not be registered.");
    }

    // ---- isSupportedAuthorizationDetailsType() ----

    @Test
    public void shouldReturnFalseForNullType() {

        assertFalse(factory.isSupportedAuthorizationDetailsType(null));
    }

    @Test
    public void shouldReturnFalseForEmptyStringType() {

        assertFalse(factory.isSupportedAuthorizationDetailsType(""));
    }

    @Test
    public void shouldReturnFalseForBlankStringType() {

        assertFalse(factory.isSupportedAuthorizationDetailsType("   "));
    }

    @Test
    public void shouldReturnTrueForSupportedType() throws APIResourceMgtException {

        AuthorizationDetailsType detailsType = new AuthorizationDetailsType();
        detailsType.setType(TEST_TYPE);

        when(typeManagerMock.getAuthorizationDetailsTypes(anyString(), anyString()))
                .thenReturn(Arrays.asList(detailsType));

        assertTrue(factory.isSupportedAuthorizationDetailsType(TEST_TYPE));
    }

    @Test
    public void shouldReturnFalseForUnsupportedType() throws APIResourceMgtException {

        AuthorizationDetailsType detailsType = new AuthorizationDetailsType();
        detailsType.setType(TEST_TYPE);

        when(typeManagerMock.getAuthorizationDetailsTypes(anyString(), anyString()))
                .thenReturn(Arrays.asList(detailsType));

        assertFalse(factory.isSupportedAuthorizationDetailsType("unsupported_type"));
    }

    // ---- getSupportedAuthorizationDetailTypes() ----

    @Test
    public void shouldReturnSetOfTypesWhenManagerReturnsTypes() throws APIResourceMgtException {

        AuthorizationDetailsType type1 = new AuthorizationDetailsType();
        type1.setType(TEST_TYPE);
        AuthorizationDetailsType type2 = new AuthorizationDetailsType();
        type2.setType("another_type");

        when(typeManagerMock.getAuthorizationDetailsTypes(anyString(), anyString()))
                .thenReturn(Arrays.asList(type1, type2));

        Set<String> result = factory.getSupportedAuthorizationDetailTypes();
        assertEquals(result.size(), 2);
        assertTrue(result.contains(TEST_TYPE));
        assertTrue(result.contains("another_type"));
    }

    @Test
    public void shouldReturnEmptySetWhenManagerReturnsNull() throws APIResourceMgtException {

        when(typeManagerMock.getAuthorizationDetailsTypes(anyString(), anyString())).thenReturn(null);

        Set<String> result = factory.getSupportedAuthorizationDetailTypes();
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    @Test
    public void shouldReturnEmptySetWhenManagerThrowsException() throws APIResourceMgtException {

        when(typeManagerMock.getAuthorizationDetailsTypes(anyString(), anyString()))
                .thenThrow(new APIResourceMgtException("Test error"));

        Set<String> result = factory.getSupportedAuthorizationDetailTypes();
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }
}
