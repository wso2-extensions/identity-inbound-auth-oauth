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
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.context.internal.OSGiDataHolder;
import org.wso2.carbon.identity.oauth.dcr.bean.Application;
import org.wso2.carbon.identity.oauth.dcr.bean.ApplicationUpdateRequest;
import org.wso2.carbon.identity.oauth.dcr.exception.DCRMException;
import org.wso2.carbon.identity.oauth.dcr.exception.DCRMServerException;
import org.wso2.carbon.identity.oauth.dcr.service.DCRMService;
import org.wso2.carbon.identity.oauth2.dcr.endpoint.Exceptions.DCRMEndpointException;
import org.wso2.carbon.identity.oauth2.dcr.endpoint.TestUtil;
import org.wso2.carbon.identity.oauth2.dcr.endpoint.dto.RegistrationRequestDTO;
import org.wso2.carbon.identity.oauth2.dcr.endpoint.dto.UpdateRequestDTO;
import org.wso2.carbon.identity.oauth2.dcr.endpoint.util.DCRMUtils;

import javax.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.List;

import static org.mockito.Matchers.any;
import static org.powermock.api.mockito.PowerMockito.doThrow;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;
import static org.powermock.api.mockito.PowerMockito.doNothing;

@PrepareForTest({BundleContext.class, ServiceTracker.class, PrivilegedCarbonContext.class, DCRMService.class})
public class RegisterApiServiceImplTest extends PowerMockTestCase {

    private RegisterApiServiceImpl registerApiService = null;
    private Application application = null;
    private List<String> redirectUris = new ArrayList<>();

    private String validclientId;

    @Mock
    BundleContext bundleContext;

    @Mock
    ServiceTracker serviceTracker ;

    @Mock
    private DCRMService dcrmService;

    @BeforeMethod
    public void setUp() throws Exception {
        //Initializing variables
        registerApiService = new RegisterApiServiceImpl();
        validclientId = "N2QqQluzQuL5X6CtM3KZwqzLQhUa";
        application = new Application();
        redirectUris.add("https://op.certification.openid.net:60845/authz_cb");
        application.setClient_name("Application");
        application.setClient_id("N2QqQluzQuL5X6CtM3KZwqzLQhUa");
        application.setClient_secret("4AXWrN88aEfMvq2h_G0dN05KRsUa");
        application.setRedirect_uris(redirectUris);

        //Get OSGIservice by starting the tenant flow.
        whenNew(ServiceTracker.class).withAnyArguments().thenReturn(serviceTracker);
        TestUtil.startTenantFlow("carbon.super");
        Object[] services = new Object[1];
        services[0] = dcrmService;
        when(serviceTracker.getServices()).thenReturn(services);
        OSGiDataHolder.getInstance().setBundleContext(bundleContext);
    }

    @Test
    public  void testDeleteApplication() throws Exception {
        doNothing().when(dcrmService).deleteApplication(validclientId);
        Assert.assertEquals(registerApiService.deleteApplication(validclientId).getStatus(),Response.Status.NO_CONTENT.getStatusCode());

    }

    @Test
    public  void testDeleteApplicationServerException() throws Exception {

        doThrow(new DCRMServerException("Server")).when(dcrmService).deleteApplication(validclientId);
        try {
            registerApiService.deleteApplication(validclientId);
        } catch (DCRMEndpointException e) {
            Assert.assertEquals(e.getResponse().getStatus(),Response.Status.INTERNAL_SERVER_ERROR.getStatusCode());
        }
    }

    @Test
    public  void testGetApplication() throws Exception {
        when(dcrmService.getApplication(validclientId)).thenReturn(application);
        Assert.assertEquals(registerApiService.getApplication(validclientId).getStatus(),Response.Status.OK.getStatusCode());

    }

    @Test
    public  void testGetApplicationServerException() throws DCRMException {
        when(dcrmService.getApplication("N2QqQluzQuL5X6CtM3KZwqzLQxxx")).
                thenThrow(new DCRMServerException("This is a server exception"));

        try {
            registerApiService.getApplication("N2QqQluzQuL5X6CtM3KZwqzLQxxx");
        } catch (DCRMEndpointException e){
            Assert.assertEquals(e.getResponse().getStatus(),Response.Status.INTERNAL_SERVER_ERROR.getStatusCode());
        }

    }

    @Test
    public  void testRegisterApplication() throws Exception {
        RegistrationRequestDTO registrationRequestDTO = new RegistrationRequestDTO();
        registrationRequestDTO.setClientName("app1");
        when(dcrmService.registerApplication
                (DCRMUtils.getApplicationRegistrationRequest(registrationRequestDTO)))
                .thenReturn(application);
        Assert.assertEquals(registerApiService.registerApplication(registrationRequestDTO)
                .getStatus(),Response.Status.CREATED.getStatusCode());

    }

    @Test
    public  void testUpdateApplicationServerException() throws Exception {
        UpdateRequestDTO updateRequestDTO = new UpdateRequestDTO();
        doThrow(new DCRMServerException("Server")).when(dcrmService).updateApplication
                (any(ApplicationUpdateRequest.class),any(String.class));
        try {
            registerApiService.updateApplication(updateRequestDTO,validclientId);
        } catch (DCRMEndpointException e) {
            Assert.assertEquals(e.getResponse().getStatus(),Response.Status.INTERNAL_SERVER_ERROR.getStatusCode());
        }
    }

    @Test
    public  void testUpdateApplication() throws Exception {
        UpdateRequestDTO updateRequestDTO1 = new UpdateRequestDTO();
        updateRequestDTO1.setClientName("Client1");
        String clientID = "clientID1";
        when(dcrmService.updateApplication
                (DCRMUtils.getApplicationUpdateRequest(updateRequestDTO1),clientID))
                .thenReturn(application);
        Assert.assertEquals(registerApiService.updateApplication(updateRequestDTO1,clientID)
                .getStatus(),Response.Status.OK.getStatusCode());

    }

}
