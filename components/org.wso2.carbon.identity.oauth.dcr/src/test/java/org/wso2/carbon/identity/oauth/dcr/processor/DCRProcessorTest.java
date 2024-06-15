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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.dcr.processor;

import org.mockito.MockedStatic;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkClientException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.dcr.DCRException;
import org.wso2.carbon.identity.oauth.dcr.context.DCRMessageContext;
import org.wso2.carbon.identity.oauth.dcr.handler.RegistrationHandler;
import org.wso2.carbon.identity.oauth.dcr.handler.UnRegistrationHandler;
import org.wso2.carbon.identity.oauth.dcr.model.RegistrationRequest;
import org.wso2.carbon.identity.oauth.dcr.model.UnregistrationRequest;
import org.wso2.carbon.identity.oauth.dcr.util.DCRConstants;
import org.wso2.carbon.identity.oauth.dcr.util.ErrorCodes;
import org.wso2.carbon.identity.oauth.dcr.util.HandlerManager;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.fail;

/**
 * Unit test covering DCRProcessor
 */
public class DCRProcessorTest {

    private DCRProcessor dcrProcessor;
    private IdentityMessageContext mockIdentityMessageContext;
    private IdentityRequest mockIdentityRequest;
    private HandlerManager mockHandlerManager;

    @BeforeMethod
    public void setUp() {

        dcrProcessor = new DCRProcessor();
    }

    @Test
    public void testGetCallbackPath() throws Exception {

        mockIdentityMessageContext = mock(IdentityMessageContext.class);
        assertNull(dcrProcessor.getCallbackPath(mockIdentityMessageContext));
    }

    @DataProvider(name = "instanceTypeprovider")
    public Object[][] getInstanceType() throws FrameworkClientException {

        RegistrationRequest registrationRequest = mock(RegistrationRequest.class);
        UnregistrationRequest unregistrationRequest = mock(UnregistrationRequest.class);
        return new Object[][]{
                {"RegistrationRequest", registrationRequest},
                {"UnregistrationRequest", unregistrationRequest}
        };
    }

    @Test(dataProvider = "instanceTypeprovider")
    public void testProcessWithIdentityRegisterEnabled(String request, Object identityRequest) throws Exception {

        mockHandlerManager = mock(HandlerManager.class);

        try (MockedStatic<HandlerManager> handlerManager = mockStatic(HandlerManager.class);
             MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class);) {
            handlerManager.when(HandlerManager::getInstance).thenReturn(mockHandlerManager);

            identityUtil.when(() -> IdentityUtil.isLegacyFeatureEnabled(DCRConstants.DCR_ID, DCRConstants.DCR_VERSION))
                    .thenReturn(true);

            if (request.equals("RegistrationRequest")) {
                RegistrationHandler registrationHandler = mock(RegistrationHandler.class);
                when(mockHandlerManager.getRegistrationHandler(any(DCRMessageContext.class))).thenReturn(
                        registrationHandler);

                when(registrationHandler.handle(any(DCRMessageContext.class))).thenReturn(new IdentityResponse.
                        IdentityResponseBuilder());
                assertNotNull(dcrProcessor.process((RegistrationRequest) identityRequest));
            } else if (request.equals("UnregistrationRequest")) {
                UnRegistrationHandler unRegistrationHandler = mock(UnRegistrationHandler.class);
                when(mockHandlerManager.getUnRegistrationHandler(any(DCRMessageContext.class))).thenReturn(
                        unRegistrationHandler);

                when(unRegistrationHandler.handle(any(DCRMessageContext.class))).thenReturn(new IdentityResponse.
                        IdentityResponseBuilder());
                assertNotNull(dcrProcessor.process((UnregistrationRequest) identityRequest));
            }
        }
    }

    @Test(dataProvider = "instanceTypeprovider")
    public void testProcessWithIdentityRegisterDisabled(String request, Object identityRequest) throws Exception {

        mockHandlerManager = mock(HandlerManager.class);

        try (MockedStatic<HandlerManager> handlerManager = mockStatic(HandlerManager.class);) {
            handlerManager.when(HandlerManager::getInstance).thenReturn(mockHandlerManager);

            String errorMessage = "/identity/register API was deprecated.";

            if (request.equals("RegistrationRequest")) {
                try {
                    RegistrationHandler registrationHandler = mock(RegistrationHandler.class);
                    when(mockHandlerManager.getRegistrationHandler(any(DCRMessageContext.class))).thenReturn(
                            registrationHandler);

                    when(registrationHandler.handle(any(DCRMessageContext.class))).thenReturn(new IdentityResponse.
                            IdentityResponseBuilder());
                } catch (Exception ex) {
                    assertEquals(ex.getMessage(), errorMessage);
                }
            } else if (request.equals("UnregistrationRequest")) {
                try {
                    UnRegistrationHandler unRegistrationHandler = mock(UnRegistrationHandler.class);
                    when(mockHandlerManager.getUnRegistrationHandler(any(DCRMessageContext.class))).thenReturn(
                            unRegistrationHandler);

                    when(unRegistrationHandler.handle(any(DCRMessageContext.class))).thenReturn(new IdentityResponse.
                            IdentityResponseBuilder());
                    assertNotNull(dcrProcessor.process((UnregistrationRequest) identityRequest));
                } catch (Exception ex) {
                    assertEquals(ex.getMessage(), errorMessage);
                }
            }
        }
    }

    @DataProvider(name = "instanceType&ErrorcodeProvider")
    public Object[][] getInstanceErrorcode() throws FrameworkClientException {

        RegistrationRequest registrationRequest = mock(RegistrationRequest.class);
        UnregistrationRequest unregistrationRequest = mock(UnregistrationRequest.class);
        return new Object[][]{
                {"RegistrationRequest", registrationRequest, "dummyErrorCode"},
                {"RegistrationRequest", registrationRequest, ""},
                {"UnregistrationRequest", unregistrationRequest, "dummyErrorCode"},
                {"UnregistrationRequest", unregistrationRequest, ""}
        };
    }

    @Test(dataProvider = "instanceType&ErrorcodeProvider")
    public void testProcessWithExceptionWithIdentityRegisterEnabled(String request, Object identityRequest,
                                                                    String errorCode) throws Exception {

        mockHandlerManager = mock(HandlerManager.class);
        try (MockedStatic<HandlerManager> handlerManager = mockStatic(HandlerManager.class);
             MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class);) {

            handlerManager.when(HandlerManager::getInstance).thenReturn(mockHandlerManager);
            identityUtil.when(() -> IdentityUtil.isLegacyFeatureEnabled(DCRConstants.DCR_ID, DCRConstants.DCR_VERSION))
                    .thenReturn(true);

            if (request.equals("RegistrationRequest")) {
                RegistrationHandler registrationHandler = mock(RegistrationHandler.class);
                when(mockHandlerManager.getRegistrationHandler(any(DCRMessageContext.class))).thenReturn(
                        registrationHandler);

                if (errorCode.isEmpty()) {
                    doThrow(new DCRException("")).when(registrationHandler).handle(any(DCRMessageContext.class));
                } else {
                    doThrow(new DCRException(errorCode, "")).when(registrationHandler)
                            .handle(any(DCRMessageContext.class));
                }
                try {
                    dcrProcessor.process((RegistrationRequest) identityRequest);
                    fail("Expected exception IdentityException not thrown by process method");
                } catch (IdentityException ex) {
                    if (errorCode.isEmpty()) {
                        assertEquals(ex.getErrorCode(), ErrorCodes.BAD_REQUEST.toString());
                    } else {
                        assertEquals(ex.getErrorCode(), errorCode);
                    }
                }
            } else if (request.equals("UnregistrationRequest")) {
                UnRegistrationHandler unRegistrationHandler = mock(UnRegistrationHandler.class);
                when(mockHandlerManager.getUnRegistrationHandler(any(DCRMessageContext.class))).thenReturn(
                        unRegistrationHandler);
                if (errorCode.isEmpty()) {
                    doThrow(new DCRException("")).when(unRegistrationHandler).handle(any(DCRMessageContext.class));
                } else {
                    doThrow(new DCRException(errorCode, "")).when(unRegistrationHandler)
                            .handle(any(DCRMessageContext.class));
                }
                try {
                    dcrProcessor.process((UnregistrationRequest) identityRequest);
                    fail("Expected exception IdentityException not thrown by registerOAuthApplication");
                } catch (IdentityException ex) {
                    if (errorCode.isEmpty()) {
                        assertEquals(ex.getMessage(), ErrorCodes.BAD_REQUEST.toString());
                    } else {
                        assertEquals(ex.getMessage(), errorCode);
                    }
                }
            }
        }
    }

    @Test
    public void testGetRelyingPartyId() throws Exception {

        assertNull(dcrProcessor.getRelyingPartyId());
    }

    @Test
    public void testGetRelyingPartyIdWithArg() throws Exception {

        mockIdentityMessageContext = mock(IdentityMessageContext.class);
        assertNull(dcrProcessor.getRelyingPartyId(mockIdentityMessageContext));
    }

    @DataProvider(name = "getHandleStatus")
    public Object[][] getStatus() {

        mockIdentityRequest = mock(IdentityRequest.class);
        return new Object[][]{
                {null, "dummy/identity/dummy", false},
                {mockIdentityRequest, "dummy/identity/dummy", false},
                {mockIdentityRequest, "dummy/identity/register/", true},
                {mockIdentityRequest, "dummy/identity/register/?", true},
                {mockIdentityRequest, "dummy/identity/register/dummy", true}
        };
    }

    @Test(dataProvider = "getHandleStatus")
    public void testCanHandle(Object identityRequest, String urlPattern, boolean expected)
            throws Exception {

        when(mockIdentityRequest.getRequestURI()).thenReturn(urlPattern);
        boolean canHandle = dcrProcessor.canHandle((IdentityRequest) identityRequest);
        assertEquals(canHandle, expected);
    }

}
