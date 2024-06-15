/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * you may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.oauth.dcr.handler;

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.stubbing.Answer;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.oauth.dcr.context.DCRMessageContext;
import org.wso2.carbon.identity.oauth.dcr.model.UnregistrationRequest;
import org.wso2.carbon.identity.oauth.dcr.service.DCRManagementService;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

/**
 * Unit test covering UnRegistrationHandler
 */
@Listeners(MockitoTestNGListener.class)
public class UnRegistrationHandlerTest {

    private UnRegistrationHandler unRegistrationHandler;

    @Mock
    private DCRMessageContext mockDcrMessageContext;

    @Mock
    private UnregistrationRequest mockUnregistrationRequest;

    @Mock
    private DCRManagementService mockDCRManagementService;

    @BeforeMethod
    public void setUp() {

        unRegistrationHandler = new UnRegistrationHandler();
    }

    @Test
    public void testHandle() throws Exception {

        try (MockedStatic<DCRManagementService> dcrManagementService = mockStatic(DCRManagementService.class);) {

            when(mockDcrMessageContext.getIdentityRequest()).thenReturn(mockUnregistrationRequest);

            UnregistrationRequest.DCRUnregisterRequestBuilder dCRUnregisterRequestBuilder =
                    new UnregistrationRequest.DCRUnregisterRequestBuilder();

            String dummyUserId = "1234";
            dCRUnregisterRequestBuilder.setUserId(dummyUserId);
            String dummyApplicationName = "testApplicationname";
            dCRUnregisterRequestBuilder.setApplicationName(dummyApplicationName);
            String dummyConsumerKey = "testConsumerKey";
            dCRUnregisterRequestBuilder.setConsumerKey(dummyConsumerKey);
            UnregistrationRequest requestBuilder = dCRUnregisterRequestBuilder.build();

            dcrManagementService.when(DCRManagementService::getInstance).thenReturn(mockDCRManagementService);
            when(mockDcrMessageContext.getIdentityRequest()).thenReturn(requestBuilder);

            final String[] params = new String[3];
            doAnswer((Answer<Object>) invocation -> {

                params[0] = (String) invocation.getArguments()[0];
                params[1] = (String) invocation.getArguments()[1];
                params[2] = (String) invocation.getArguments()[2];
                return null;
            }).when(mockDCRManagementService).unregisterOAuthApplication(anyString(), anyString(), anyString());

            IdentityResponse.IdentityResponseBuilder identityResponseBuilder =
                    unRegistrationHandler.handle(mockDcrMessageContext);

            assertNotNull(identityResponseBuilder,
                    "Expected response builder is different from the actual");
            assertEquals(params[0], dummyUserId, "Expected tenant user Id is not equal to the actual");
            assertEquals(params[1], dummyApplicationName, "Expected application name is not equal to the actual");
            assertEquals(params[2], dummyConsumerKey, "Expected consumer key is not equal to the actual");
        }
    }
}
