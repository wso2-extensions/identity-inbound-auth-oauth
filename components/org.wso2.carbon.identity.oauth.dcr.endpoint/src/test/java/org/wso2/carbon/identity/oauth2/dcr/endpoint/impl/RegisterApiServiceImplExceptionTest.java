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
import org.osgi.framework.BundleContext;
import org.osgi.util.tracker.ServiceTracker;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.context.internal.OSGiDataHolder;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.oauth.OAuthAdminService;
import org.wso2.carbon.identity.oauth.dcr.exception.DCRMException;
import org.wso2.carbon.identity.oauth.dcr.internal.DCRDataHolder;
import org.wso2.carbon.identity.oauth.dcr.service.DCRMService;
import org.wso2.carbon.identity.oauth2.dcr.endpoint.Exceptions.DCRMEndpointException;
import org.wso2.carbon.identity.oauth2.dcr.endpoint.TestUtil;
import org.wso2.carbon.identity.oauth2.dcr.endpoint.dto.RegistrationRequestDTO;
import org.wso2.carbon.identity.oauth2.dcr.endpoint.dto.UpdateRequestDTO;

import javax.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.List;

import static org.mockito.Matchers.any;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;
import static org.testng.Assert.assertEquals;

@PrepareForTest({BundleContext.class, ServiceTracker.class, PrivilegedCarbonContext.class,  DCRDataHolder.class, ApplicationManagementService.class, ServiceProvider.class, OAuthAdminService.class})
public class RegisterApiServiceImplExceptionTest extends PowerMockTestCase {

    private RegisterApiServiceImpl registerApiService = null;
    private DCRMService dcrmService = new DCRMService();

    @Mock
    BundleContext bundleContext;

    @Mock
    ServiceTracker serviceTracker ;

    @Mock
    DCRDataHolder dataHolder;

    @Mock
    ApplicationManagementService applicationManagementService  ;

    @Mock
    ServiceProvider serviceProvider;

    @Mock
    OAuthAdminService oAuthAdminService;

    @BeforeMethod
    public void setUp() throws Exception {
        //Initializing variables
        registerApiService = new RegisterApiServiceImpl();

        //Get OSGIservice by starting the tenant flow.
        whenNew(ServiceTracker.class).withAnyArguments().thenReturn(serviceTracker);
        TestUtil.startTenantFlow(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        Object[] services = new Object[1];
        services[0] = dcrmService;
        when(serviceTracker.getServices()).thenReturn(services);
        OSGiDataHolder.getInstance().setBundleContext(bundleContext);
    }

    @Test
    public  void testDeleteApplicationClientException() throws Exception {
        try {
            registerApiService.deleteApplication("");
        } catch (DCRMEndpointException e){
            assertEquals(e.getResponse().getStatus(), Response.Status.BAD_REQUEST.getStatusCode());
        }
    }

    @Test
    public  void testDeleteApplicationThrowableException() throws DCRMException {
        //Test for invalid client id.
        try {
            registerApiService.deleteApplication("ClientIDInvalid");
        } catch (DCRMEndpointException e){
            assertEquals(e.getResponse().getStatus(),Response.Status.INTERNAL_SERVER_ERROR.getStatusCode());
        }
    }

    @Test
    public  void testGetApplicationClientException() throws Exception {
        try {
            registerApiService.getApplication("");
        } catch (DCRMEndpointException e){
            assertEquals(e.getResponse().getStatus(), Response.Status.BAD_REQUEST.getStatusCode());
        }
    }

    @Test
    public  void testGetApplicationThrowableException() throws DCRMException {
        //Test for invalid client id.
        try {
            registerApiService.getApplication("N2QqQluzQuL5X6CtM3KZwqzLQyyy");
        } catch (DCRMEndpointException e){
            assertEquals(e.getResponse().getStatus(),Response.Status.INTERNAL_SERVER_ERROR.getStatusCode());
        }
    }

    @Test
    public  void testRegisterApplicationClientException() throws DCRMException {

        List<String> granttypes = new ArrayList<>();
        granttypes.add("code");
        List<String> redirectUris = new ArrayList<>();
        redirectUris.add("https://op.certification.openid.net:60845/authz_cb");
        RegistrationRequestDTO registrationRequestDTO = new RegistrationRequestDTO();
        registrationRequestDTO.setClientName("Test App");
        registrationRequestDTO.setGrantTypes(granttypes);
        registrationRequestDTO.setRedirectUris(redirectUris);

        mockStatic(DCRDataHolder.class);
        when(DCRDataHolder.getInstance()).thenReturn(dataHolder);
        when(dataHolder.getApplicationManagementService()).thenReturn( applicationManagementService);

        try {
            registerApiService.registerApplication(registrationRequestDTO);
        } catch (DCRMEndpointException e){
            assertEquals(e.getResponse().getStatus(),Response.Status.BAD_REQUEST.getStatusCode());
        }
    }

    @Test
    public  void testRegisterApplicationServerException() throws DCRMException, IdentityApplicationManagementException {

        List<String> granttypes = new ArrayList<>();
        granttypes.add("code");
        List<String> redirectUris = new ArrayList<>();
        redirectUris.add("https://op.certification.openid.net:60845/authz_cb");
        RegistrationRequestDTO registrationRequestDTO = new RegistrationRequestDTO();
        registrationRequestDTO.setClientName("Test App");
        registrationRequestDTO.setGrantTypes(granttypes);
        registrationRequestDTO.setRedirectUris(redirectUris);

        mockStatic(DCRDataHolder.class);
        when(DCRDataHolder.getInstance()).thenReturn(dataHolder);
        when(dataHolder.getApplicationManagementService()).thenReturn( applicationManagementService);
        when(applicationManagementService.getServiceProvider(any(String.class),any(String.class))).
                thenThrow(new IdentityApplicationManagementException("execption"));

        try {
            registerApiService.registerApplication(registrationRequestDTO);
        } catch (DCRMEndpointException e){
            assertEquals(e.getResponse().getStatus(),Response.Status.BAD_REQUEST.getStatusCode());
        }

    }

    @Test
    public  void testRegisterApplicationThrowableException() throws DCRMException {
        //Test for invalid client id.
        RegistrationRequestDTO registrationRequestDTO = new RegistrationRequestDTO();
        registrationRequestDTO.setClientName("");
        try {
            registerApiService.registerApplication(registrationRequestDTO);
        } catch (DCRMEndpointException e){
            assertEquals(e.getResponse().getStatus(),Response.Status.INTERNAL_SERVER_ERROR.getStatusCode());
        }
    }

    @Test
    public  void testUpdateApplicationClientException() throws DCRMException {

        List<String> granttypes = new ArrayList<>();
        granttypes.add("code");
        List<String> redirectUris = new ArrayList<>();
        redirectUris.add("https://op.certification.openid.net:60845/authz_cb");
        UpdateRequestDTO updateRequestDTO = new UpdateRequestDTO();
        updateRequestDTO.setClientName("Test App");
        updateRequestDTO.setGrantTypes(granttypes);
        updateRequestDTO.setRedirectUris(redirectUris);

        mockStatic(DCRDataHolder.class);
        when(DCRDataHolder.getInstance()).thenReturn(dataHolder);
        when(dataHolder.getApplicationManagementService()).thenReturn( applicationManagementService);

        //Test when clientID is null
        try {
            registerApiService.updateApplication(updateRequestDTO,"");
        } catch (DCRMEndpointException e){
            assertEquals(e.getResponse().getStatus(),Response.Status.BAD_REQUEST.getStatusCode());
        }
    }

    @Test
    public  void testUpdateApplicationThrowableException() throws DCRMException {
        //Test for invalid client id.
        UpdateRequestDTO updateRequestDTO = new UpdateRequestDTO();
        updateRequestDTO.setClientName("");
        try {
            registerApiService.updateApplication(updateRequestDTO, "ClientID");
        } catch (DCRMEndpointException e){
            assertEquals(e.getResponse().getStatus(),Response.Status.INTERNAL_SERVER_ERROR.getStatusCode());
        }
    }

}

