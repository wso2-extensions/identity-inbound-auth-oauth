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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.dcr.endpoint.impl;

import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.testng.MockitoTestNGListener;
import org.osgi.framework.BundleContext;
import org.osgi.util.tracker.ServiceTracker;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.context.internal.OSGiDataHolder;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.oauth.dcr.exception.DCRMException;
import org.wso2.carbon.identity.oauth.dcr.internal.DCRDataHolder;
import org.wso2.carbon.identity.oauth.dcr.service.DCRMService;
import org.wso2.carbon.identity.oauth2.dcr.endpoint.TestUtil;
import org.wso2.carbon.identity.oauth2.dcr.endpoint.dto.RegistrationRequestDTO;
import org.wso2.carbon.identity.oauth2.dcr.endpoint.dto.UpdateRequestDTO;
import org.wso2.carbon.identity.oauth2.dcr.endpoint.exceptions.DCRMEndpointException;
import org.wso2.carbon.identity.oauth2.dcr.endpoint.util.DCRMUtils;

import java.util.ArrayList;
import java.util.List;

import javax.ws.rs.core.Response;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;

@Listeners(MockitoTestNGListener.class)
public class RegisterApiServiceImplExceptionTest {

    private RegisterApiServiceImpl registerApiService = null;
    private DCRMService dcrmService = new DCRMService();

    @Mock
    BundleContext bundleContext;

    @Mock
    DCRDataHolder dataHolder;

    @Mock
    ApplicationManagementService applicationManagementService;

    @Mock
    DCRMService mockedDCRMService;

    MockedConstruction<ServiceTracker> mockedConstruction;

    @BeforeMethod
    public void setUp() throws Exception {

        // Initializing variables.
        registerApiService = new RegisterApiServiceImpl();

        //Get OSGIservice by starting the tenant flow.
        TestUtil.startTenantFlow(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        Object[] services = new Object[1];
        services[0] = dcrmService;

        mockedConstruction = mockConstruction(ServiceTracker.class,
                (mock, context) -> {
                    when(mock.getServices()).thenReturn(services);
                });

        OSGiDataHolder.getInstance().setBundleContext(bundleContext);
    }

    @AfterMethod
    public void tearDown() {

        mockedConstruction.close();
        PrivilegedCarbonContext.endTenantFlow();
    }

    @Test
    public void testDeleteApplicationClientException() throws Exception {

        try {
            DCRMUtils.setOAuth2DCRMService(mockedDCRMService);
            registerApiService.deleteApplication("");
        } catch (DCRMEndpointException e) {
            assertEquals(e.getResponse().getStatus(), Response.Status.BAD_REQUEST.getStatusCode());
        }
    }

    @Test
    public void testDeleteApplicationThrowableException() throws DCRMException {

        // Test for invalid client id.
        try {
            registerApiService.deleteApplication("ClientIDInvalid");
        } catch (DCRMEndpointException e) {
            assertEquals(e.getResponse().getStatus(), Response.Status.INTERNAL_SERVER_ERROR.getStatusCode());
        }
    }

    @Test
    public void testGetApplicationClientException() throws Exception {

        try {
            DCRMUtils.setOAuth2DCRMService(mockedDCRMService);
            registerApiService.getApplication("");
        } catch (DCRMEndpointException e) {
            assertEquals(e.getResponse().getStatus(), Response.Status.BAD_REQUEST.getStatusCode());
        }
    }

    @Test
    public void testGetApplicationThrowableException() throws DCRMException {
        //Test for invalid client id.
        try {
            registerApiService.getApplication("N2QqQluzQuL5X6CtM3KZwqzLQyyy");
        } catch (DCRMEndpointException e) {
            assertEquals(e.getResponse().getStatus(), Response.Status.INTERNAL_SERVER_ERROR.getStatusCode());
        }
    }

    @Test
    public void testRegisterApplicationClientException() throws DCRMException {

        try (MockedStatic<DCRDataHolder> dcrDataHolder = mockStatic(DCRDataHolder.class)) {
            List<String> granttypes = new ArrayList<>();
            granttypes.add("code");
            List<String> redirectUris = new ArrayList<>();
            redirectUris.add("https://op.certification.openid.net:60845/authz_cb");
            RegistrationRequestDTO registrationRequestDTO = new RegistrationRequestDTO();
            registrationRequestDTO.setClientName("Test App");
            registrationRequestDTO.setGrantTypes(granttypes);
            registrationRequestDTO.setRedirectUris(redirectUris);
            DCRMUtils.setOAuth2DCRMService(mockedDCRMService);
            dcrDataHolder.when(DCRDataHolder::getInstance).thenReturn(dataHolder);
            lenient().when(dataHolder.getApplicationManagementService()).thenReturn(applicationManagementService);

            try {
                registerApiService.registerApplication(registrationRequestDTO);
            } catch (DCRMEndpointException e) {
                assertEquals(e.getResponse().getStatus(), Response.Status.BAD_REQUEST.getStatusCode());
            }
        }
    }

    @Test
    public void testRegisterApplicationServerException() throws DCRMException, IdentityApplicationManagementException {

        try (MockedStatic<DCRDataHolder> dcrDataHolder = mockStatic(DCRDataHolder.class)) {
            List<String> granttypes = new ArrayList<>();
            granttypes.add("code");
            List<String> redirectUris = new ArrayList<>();
            redirectUris.add("https://op.certification.openid.net:60845/authz_cb");
            RegistrationRequestDTO registrationRequestDTO = new RegistrationRequestDTO();
            registrationRequestDTO.setClientName("Test App");
            registrationRequestDTO.setGrantTypes(granttypes);
            registrationRequestDTO.setRedirectUris(redirectUris);

            DCRMUtils.setOAuth2DCRMService(mockedDCRMService);
            dcrDataHolder.when(DCRDataHolder::getInstance).thenReturn(dataHolder);
            lenient().when(dataHolder.getApplicationManagementService()).thenReturn(applicationManagementService);
            lenient().when(applicationManagementService.getServiceProvider(any(String.class), any(String.class))).
                    thenThrow(new IdentityApplicationManagementException("execption"));

            try {
                registerApiService.registerApplication(registrationRequestDTO);
            } catch (DCRMEndpointException e) {
                assertEquals(e.getResponse().getStatus(), Response.Status.BAD_REQUEST.getStatusCode());
            }
        }
    }

    @Test
    public void testRegisterApplicationThrowableException() throws DCRMException {
        //Test for invalid client id.
        RegistrationRequestDTO registrationRequestDTO = new RegistrationRequestDTO();
        registrationRequestDTO.setClientName("");
        try {
            registerApiService.registerApplication(registrationRequestDTO);
        } catch (DCRMEndpointException e) {
            assertEquals(e.getResponse().getStatus(), Response.Status.INTERNAL_SERVER_ERROR.getStatusCode());
        }
    }

    @Test
    public void testUpdateApplicationClientException() throws DCRMException {

        try (MockedStatic<DCRDataHolder> dcrDataHolder = mockStatic(DCRDataHolder.class)) {
            List<String> granttypes = new ArrayList<>();
            granttypes.add("code");
            List<String> redirectUris = new ArrayList<>();
            redirectUris.add("https://op.certification.openid.net:60845/authz_cb");
            UpdateRequestDTO updateRequestDTO = new UpdateRequestDTO();
            updateRequestDTO.setClientName("Test App");
            updateRequestDTO.setGrantTypes(granttypes);
            updateRequestDTO.setRedirectUris(redirectUris);
            DCRMUtils.setOAuth2DCRMService(mockedDCRMService);
            dcrDataHolder.when(DCRDataHolder::getInstance).thenReturn(dataHolder);
            lenient().when(dataHolder.getApplicationManagementService()).thenReturn(applicationManagementService);

            // Test when clientID is null.
            try {
                registerApiService.updateApplication(updateRequestDTO, "");
            } catch (DCRMEndpointException e) {
                assertEquals(e.getResponse().getStatus(), Response.Status.BAD_REQUEST.getStatusCode());
            }
        }
    }

    @Test
    public void testUpdateApplicationThrowableException() throws DCRMException {
        //Test for invalid client id.
        UpdateRequestDTO updateRequestDTO = new UpdateRequestDTO();
        updateRequestDTO.setClientName("");
        try {
            registerApiService.updateApplication(updateRequestDTO, "ClientID");
        } catch (DCRMEndpointException e) {
            assertEquals(e.getResponse().getStatus(), Response.Status.INTERNAL_SERVER_ERROR.getStatusCode());
        }
    }
}
