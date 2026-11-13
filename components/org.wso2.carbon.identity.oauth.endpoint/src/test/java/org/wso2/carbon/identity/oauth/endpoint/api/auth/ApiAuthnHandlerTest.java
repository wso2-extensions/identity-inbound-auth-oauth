/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.endpoint.api.auth;

import org.mockito.MockedStatic;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.exception.auth.service.AuthServiceException;
import org.wso2.carbon.identity.application.authentication.framework.model.AdditionalData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorData;
import org.wso2.carbon.identity.application.authentication.framework.model.auth.service.AuthServiceResponse;
import org.wso2.carbon.identity.application.authentication.framework.model.auth.service.AuthServiceResponseData;
import org.wso2.carbon.identity.application.authentication.framework.util.auth.service.AuthServiceConstants;
import org.wso2.carbon.identity.oauth.endpoint.api.auth.model.AuthResponse;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.util.Collections;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

/**
 * Tests for ApiAuthnHandler.
 */
public class ApiAuthnHandlerTest {

    private ApiAuthnHandler apiAuthnHandler;
    private MockedStatic<OAuth2Util> mockedOAuth2Util;

    @BeforeMethod
    public void setUp() {

        apiAuthnHandler = new ApiAuthnHandler();
        mockedOAuth2Util = mockStatic(OAuth2Util.class);
        mockedOAuth2Util.when(() -> OAuth2Util.buildServiceUrl(any(), any(), any()))
                .thenReturn("https://localhost:9443/oauth2/authn");
    }

    @AfterMethod
    public void tearDown() {

        mockedOAuth2Util.close();
    }

    @Test
    public void testHandleResponseWithEmptyRequiredParamsAndAdditionalData() throws AuthServiceException {

        AuthServiceResponse authServiceResponse = mock(AuthServiceResponse.class);
        when(authServiceResponse.getSessionDataKey()).thenReturn("test-session-key");
        when(authServiceResponse.getFlowStatus()).thenReturn(AuthServiceConstants.FlowStatus.INCOMPLETE);
        when(authServiceResponse.getErrorInfo()).thenReturn(Optional.empty());

        AuthenticatorData authenticatorData = new AuthenticatorData();
        authenticatorData.setName("BasicAuthenticator");
        authenticatorData.setDisplayName("Username & Password");
        authenticatorData.setIdp("LOCAL");
        // requiredParams is empty by default — only additionalData is set to trigger the new branch
        AdditionalData additionalData = new AdditionalData();
        additionalData.setRedirectUrl("https://localhost:9443/login");
        authenticatorData.setAdditionalData(additionalData);

        AuthServiceResponseData responseData = new AuthServiceResponseData();
        responseData.setAuthenticatorOptions(Collections.singletonList(authenticatorData));
        when(authServiceResponse.getData()).thenReturn(Optional.of(responseData));

        AuthResponse authResponse = apiAuthnHandler.handleResponse(authServiceResponse);

        Assert.assertNotNull(authResponse);
        Assert.assertEquals(authResponse.getFlowId(), "test-session-key");
        Assert.assertNotNull(authResponse.getNextStep().getAuthenticators());
        Assert.assertEquals(authResponse.getNextStep().getAuthenticators().size(), 1);
        // additionalData must be populated because isAdditionalAuthenticatorDataAvailable() returned true
        Assert.assertNotNull(
                authResponse.getNextStep().getAuthenticators().get(0).getMetadata().getAdditionalData());
    }

    @Test
    public void testHandleResponseWithEmptyRequiredParamsAndNullAdditionalData() throws AuthServiceException {

        AuthServiceResponse authServiceResponse = mock(AuthServiceResponse.class);
        when(authServiceResponse.getSessionDataKey()).thenReturn("test-session-key");
        when(authServiceResponse.getFlowStatus()).thenReturn(AuthServiceConstants.FlowStatus.INCOMPLETE);
        when(authServiceResponse.getErrorInfo()).thenReturn(Optional.empty());

        AuthenticatorData authenticatorData = new AuthenticatorData();
        authenticatorData.setName("BasicAuthenticator");
        authenticatorData.setDisplayName("Username & Password");
        authenticatorData.setIdp("LOCAL");
        // both requiredParams and additionalData are empty/null → isAdditionalAuthenticatorDataAvailable() = false

        AuthServiceResponseData responseData = new AuthServiceResponseData();
        responseData.setAuthenticatorOptions(Collections.singletonList(authenticatorData));
        when(authServiceResponse.getData()).thenReturn(Optional.of(responseData));

        AuthResponse authResponse = apiAuthnHandler.handleResponse(authServiceResponse);

        Assert.assertNotNull(authResponse);
        // additionalData defaults to an empty map when isAdditionalAuthenticatorDataAvailable() returns false
        Assert.assertTrue(
                authResponse.getNextStep().getAuthenticators().get(0).getMetadata().getAdditionalData().isEmpty());
    }
}
