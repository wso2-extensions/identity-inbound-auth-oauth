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

import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkClientException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.oauth.dcr.DCRException;
import org.wso2.carbon.identity.oauth.dcr.context.DCRMessageContext;
import org.wso2.carbon.identity.oauth.dcr.handler.RegistrationHandler;
import org.wso2.carbon.identity.oauth.dcr.handler.UnRegistrationHandler;
import org.wso2.carbon.identity.oauth.dcr.model.RegistrationRequest;
import org.wso2.carbon.identity.oauth.dcr.model.UnregistrationRequest;
import org.wso2.carbon.identity.oauth.dcr.util.ErrorCodes;
import org.wso2.carbon.identity.oauth.dcr.util.HandlerManager;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;

import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.whenNew;
import static org.powermock.api.mockito.PowerMockito.doThrow;
import static org.powermock.api.mockito.PowerMockito.mockStatic;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.fail;
import static org.testng.Assert.assertNull;

/**
 * Unit test covering DCRProcessor
 */
@PrepareForTest({HandlerManager.class, DCRProcessor.class})
public class DCRProcessorTest extends PowerMockIdentityBaseTest {

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
    public void testProcess(String request, Object identityRequest) throws Exception {

        mockHandlerManager = mock(HandlerManager.class);

        mockStatic(HandlerManager.class);
        when(HandlerManager.getInstance()).thenReturn(mockHandlerManager);

        DCRMessageContext dcrMessageContext = mock(DCRMessageContext.class);
        whenNew(DCRMessageContext.class).withArguments(identityRequest).thenReturn(dcrMessageContext);

        if (request.equals("RegistrationRequest")) {
            RegistrationHandler registrationHandler = mock(RegistrationHandler.class);
            when(mockHandlerManager.getRegistrationHandler(dcrMessageContext)).thenReturn(registrationHandler);

            when(registrationHandler.handle(dcrMessageContext)).thenReturn(new IdentityResponse.
                    IdentityResponseBuilder());
            assertNotNull(dcrProcessor.process((RegistrationRequest) identityRequest));
        } else if (request.equals("UnregistrationRequest")) {
            UnRegistrationHandler unRegistrationHandler = mock(UnRegistrationHandler.class);
            when(mockHandlerManager.getUnRegistrationHandler(dcrMessageContext)).thenReturn(unRegistrationHandler);

            when(unRegistrationHandler.handle(dcrMessageContext)).thenReturn(new IdentityResponse.
                    IdentityResponseBuilder());
            assertNotNull(dcrProcessor.process((UnregistrationRequest) identityRequest));
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
    public void testProcessWithException(String request, Object identityRequest, String errorCode) throws Exception {

        mockHandlerManager = mock(HandlerManager.class);

        mockStatic(HandlerManager.class);
        when(HandlerManager.getInstance()).thenReturn(mockHandlerManager);

        DCRMessageContext dcrMessageContext = mock(DCRMessageContext.class);
        whenNew(DCRMessageContext.class).withArguments(identityRequest).thenReturn(dcrMessageContext);

        if (request.equals("RegistrationRequest")) {
            RegistrationHandler registrationHandler = mock(RegistrationHandler.class);
            when(mockHandlerManager.getRegistrationHandler(dcrMessageContext)).thenReturn(registrationHandler);

            if (errorCode.isEmpty()) {
                doThrow(new DCRException("")).when(registrationHandler).handle(dcrMessageContext);
            } else {
                doThrow(new DCRException(errorCode, "")).when(registrationHandler).handle(dcrMessageContext);
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
            when(mockHandlerManager.getUnRegistrationHandler(dcrMessageContext)).thenReturn(unRegistrationHandler);
            if (errorCode.isEmpty()) {
                doThrow(new DCRException("")).when(unRegistrationHandler).handle(dcrMessageContext);
            } else {
                doThrow(new DCRException(errorCode, "")).when(unRegistrationHandler).handle(dcrMessageContext);
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
