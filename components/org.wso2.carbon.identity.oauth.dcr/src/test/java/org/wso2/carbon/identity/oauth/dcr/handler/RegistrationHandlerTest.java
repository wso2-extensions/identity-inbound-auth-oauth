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
import org.mockito.testng.MockitoTestNGListener;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth.dcr.context.DCRMessageContext;
import org.wso2.carbon.identity.oauth.dcr.model.RegistrationRequest;
import org.wso2.carbon.identity.oauth.dcr.model.RegistrationRequestProfile;
import org.wso2.carbon.identity.oauth.dcr.model.RegistrationResponse;
import org.wso2.carbon.identity.oauth.dcr.model.RegistrationResponseProfile;
import org.wso2.carbon.identity.oauth.dcr.service.DCRManagementService;

import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

/**
 * Unit test covering RegistrationHandler
 */
@Listeners(MockitoTestNGListener.class)
public class RegistrationHandlerTest {

    private RegistrationHandler registrationHandler;

    @Mock
    private RegistrationRequest mockRegisterRequest;

    @Mock
    private DCRMessageContext mockDcrMessageContext;

    @Mock
    private RegistrationResponseProfile mockRegistrationResponseProfile;

    @Mock
    private DCRManagementService mockDCRManagementService;

    @BeforeMethod
    public void setUp() {

        registrationHandler = new RegistrationHandler();
    }

    @Test
    public void testHandle() throws Exception {

        try (MockedStatic<DCRManagementService> dcrManagementService = mockStatic(DCRManagementService.class);) {
            RegistrationRequestProfile mockRegistrationRequestProfile = new RegistrationRequestProfile();

            when(mockDcrMessageContext.getIdentityRequest()).thenReturn(mockRegisterRequest);
            when(mockRegisterRequest.getRegistrationRequestProfile()).thenReturn(mockRegistrationRequestProfile);
            String testTenantDomain = "testTenantDomain";
            when(mockRegisterRequest.getTenantDomain()).thenReturn(testTenantDomain);

            dcrManagementService.when(DCRManagementService::getInstance).thenReturn(mockDCRManagementService);

            when(mockDCRManagementService.registerOAuthApplication(mockRegistrationRequestProfile)).
                    thenReturn(mockRegistrationResponseProfile);

            RegistrationResponse.DCRRegisterResponseBuilder identityResponseBuilder =
                    (RegistrationResponse.DCRRegisterResponseBuilder) registrationHandler.handle(mockDcrMessageContext);
            RegistrationResponseProfile registrationResponseProfile =
                    identityResponseBuilder.build().getRegistrationResponseProfile();
            assertNotNull(registrationResponseProfile, "Expected response builder is different from the actual");
            assertEquals(mockRegistrationRequestProfile.getTenantDomain(), testTenantDomain,
                    "Expected tenant domain is not equal to the actual tenant domain");
        }
    }
}
