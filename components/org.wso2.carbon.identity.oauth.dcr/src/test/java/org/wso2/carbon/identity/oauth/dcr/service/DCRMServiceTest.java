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

package org.wso2.carbon.identity.oauth.dcr.service;

import org.apache.commons.lang.StringUtils;
import org.mockito.internal.util.reflection.Whitebox;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.OAuthAdminService;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dcr.DCRMConstants;
import org.wso2.carbon.identity.oauth.dcr.bean.Application;
import org.wso2.carbon.identity.oauth.dcr.bean.ApplicationRegistrationRequest;
import org.wso2.carbon.identity.oauth.dcr.bean.ApplicationUpdateRequest;
import org.wso2.carbon.identity.oauth.dcr.exception.DCRMException;
import org.wso2.carbon.identity.oauth.dcr.internal.DCRDataHolder;
import org.wso2.carbon.identity.oauth.dto.OAuthConsumerAppDTO;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;

import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import static org.mockito.Matchers.any;
import static org.powermock.api.mockito.PowerMockito.doNothing;
import static org.powermock.api.mockito.PowerMockito.doThrow;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.fail;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth10AParams.OAUTH_VERSION;

/**
 * Unit test covering DCRMService
 */
@PrepareForTest({DCRMService.class, ServiceProvider.class, IdentityProviderManager.class})
public class DCRMServiceTest extends PowerMockTestCase {

    private DCRMService dcrmService;

    private OAuthAdminService mockOAuthAdminService;
    private String dummyConsumerKey = "dummyConsumerKey";
    private ApplicationRegistrationRequest applicationRegistrationRequest;
    private String dummyClientName = "dummyClientName";
    private String dummyInvalidClientName = "dummy@ClientName";
    private List<String> dummyGrantTypes = new ArrayList<>();
    private String dummyUserName = "dummyUserName";
    private String dummyTenantDomain = "dummyTenantDomain";
    private ApplicationManagementService mockApplicationManagementService;

    @BeforeMethod
    public void setUp() {

        mockOAuthAdminService = mock(OAuthAdminService.class);
        applicationRegistrationRequest = new ApplicationRegistrationRequest();
        applicationRegistrationRequest.setClientName(dummyClientName);
        dcrmService = new DCRMService();
    }

    @DataProvider(name = "DTOProvider")
    public Object[][] getDTOStatus() {

        return new String[][]{
                {null},
                {""}
        };
    }

    @Test
    public void getApplicationEmptyClientIdTest() throws DCRMException {

        try {
            dcrmService.getApplication("");
        } catch (IdentityException ex) {
            assertEquals(ex.getMessage(), "Invalid client_id");
            return;
        }
        fail("Expected exception IdentityException not thrown by getApplication method");
    }

    @Test(dataProvider = "DTOProvider")
    public void getApplicationNullDTOTest(String dtoStatus) throws Exception {

        if (dtoStatus == null) {
            when(mockOAuthAdminService.getOAuthApplicationData(dummyConsumerKey)).thenReturn(null);
            when(mockOAuthAdminService.getAllOAuthApplicationData()).thenReturn(new OAuthConsumerAppDTO[0]);
        } else {
            OAuthConsumerAppDTO dto = new OAuthConsumerAppDTO();
            dto.setApplicationName("");
            when(mockOAuthAdminService.getOAuthApplicationData(dummyConsumerKey)).thenReturn(dto);
            when(mockOAuthAdminService.getAllOAuthApplicationData()).thenReturn(new OAuthConsumerAppDTO[]{dto});
        }
        Whitebox.setInternalState(dcrmService, "oAuthAdminService", mockOAuthAdminService);
        try {
            dcrmService.getApplication(dummyConsumerKey);
        } catch (IdentityException ex) {
            assertEquals(ex.getErrorCode(), DCRMConstants.ErrorMessages.NOT_FOUND_APPLICATION_WITH_ID.toString());
            return;
        }
        fail("Expected exception IdentityException not thrown by getApplication method");
    }

    @Test
    public void getApplicationDTOTestWithIOAException() throws Exception {

        doThrow(new IdentityOAuthAdminException("")).when(mockOAuthAdminService).getOAuthApplicationData(dummyConsumerKey);

        when(mockOAuthAdminService.getAllOAuthApplicationData()).thenReturn(new OAuthConsumerAppDTO[0]);

        Whitebox.setInternalState(dcrmService, "oAuthAdminService", mockOAuthAdminService);
        try {
            dcrmService.getApplication(dummyConsumerKey);
        } catch (IdentityException ex) {
            assertEquals(ex.getErrorCode(), DCRMConstants.ErrorMessages.FAILED_TO_GET_APPLICATION_BY_ID.toString());
            return;
        }
        fail("Expected exception IdentityException not thrown by getApplication method");
    }

    @Test
    public void getApplicationDTOTestWithIOCException() throws Exception {

        doThrow(new IdentityOAuthAdminException("", new InvalidOAuthClientException(""))).when(mockOAuthAdminService)
                .getOAuthApplicationData(dummyConsumerKey);
        when(mockOAuthAdminService.getAllOAuthApplicationData()).thenReturn(new OAuthConsumerAppDTO[0]);

        Whitebox.setInternalState(dcrmService, "oAuthAdminService", mockOAuthAdminService);
        try {
            dcrmService.getApplication(dummyConsumerKey);
        } catch (IdentityException ex) {
            assertEquals(ex.getErrorCode(), DCRMConstants.ErrorMessages.NOT_FOUND_APPLICATION_WITH_ID.toString());
            return;
        }
        fail("Expected exception IdentityException not thrown by getApplication method");
    }

    @Test
    public void getApplicationDTOTest() throws Exception {

        startTenantFlow();
        OAuthConsumerAppDTO dto = new OAuthConsumerAppDTO();
        dto.setApplicationName(dummyClientName);
        String dummyConsumerSecret = "dummyConsumerSecret";
        dto.setOauthConsumerSecret(dummyConsumerSecret);
        dto.setOauthConsumerKey(dummyConsumerKey);
        String dummyCallbackUrl = "dummyCallbackUrl";
        dto.setCallbackUrl(dummyCallbackUrl);
        dto.setUsername(dummyUserName.concat("@").concat(dummyTenantDomain));

        OAuthConsumerAppDTO[] oAuthConsumerAppDTOS = new OAuthConsumerAppDTO[]{dto};

        when(mockOAuthAdminService.getOAuthApplicationData(dummyConsumerKey)).thenReturn(dto);
        when(mockOAuthAdminService.getAllOAuthApplicationData()).thenReturn(oAuthConsumerAppDTOS);

        Whitebox.setInternalState(dcrmService, "oAuthAdminService", mockOAuthAdminService);
        Application application = dcrmService.getApplication(dummyConsumerKey);

        assertEquals(application.getClient_id(), dummyConsumerKey);
        assertEquals(application.getClient_name(), dummyClientName);
        assertEquals(application.getClient_secret(), dummyConsumerSecret);
        assertEquals(application.getRedirect_uris().get(0), dummyCallbackUrl);
    }

    @Test
    public void registerApplicationTestWithExistSP() throws DCRMException, IdentityApplicationManagementException {

        dummyGrantTypes.add("dummy1");
        dummyGrantTypes.add("dummy2");

        applicationRegistrationRequest.setGrantTypes(dummyGrantTypes);

        startTenantFlow();

        mockApplicationManagementService = mock(ApplicationManagementService.class);
        DCRDataHolder dcrDataHolder = DCRDataHolder.getInstance();
        dcrDataHolder.setApplicationManagementService(mockApplicationManagementService);
        when(mockApplicationManagementService.getServiceProvider(dummyClientName, dummyTenantDomain)).thenReturn(new
                ServiceProvider());

        try {
            dcrmService.registerApplication(applicationRegistrationRequest);
        } catch (IdentityException ex) {
            assertEquals(ex.getErrorCode(), DCRMConstants.ErrorMessages.CONFLICT_EXISTING_APPLICATION.toString());
            return;
        }
        fail("Expected exception IdentityException not thrown by registerApplication method");
    }

    @Test
    public void registerApplicationTestWithFailedToGetSP() throws DCRMException,
            IdentityApplicationManagementException {

        dummyGrantTypes.add("dummy1");
        dummyGrantTypes.add("dummy2");

        applicationRegistrationRequest.setGrantTypes(dummyGrantTypes);

        startTenantFlow();

        mockApplicationManagementService = mock(ApplicationManagementService.class);
        DCRDataHolder dcrDataHolder = DCRDataHolder.getInstance();
        dcrDataHolder.setApplicationManagementService(mockApplicationManagementService);

        doThrow(new IdentityApplicationManagementException("")).when(mockApplicationManagementService)
                .getServiceProvider(dummyClientName, dummyTenantDomain);

        try {
            dcrmService.registerApplication(applicationRegistrationRequest);
        } catch (IdentityException ex) {
            assertEquals(ex.getErrorCode(), DCRMConstants.ErrorMessages.FAILED_TO_GET_SP.toString());
            return;
        }
        fail("Expected exception IdentityException not thrown by registerApplication method");
    }

    @Test
    public void registerApplicationTestWithFailedToRegisterSP() throws Exception {

        dummyGrantTypes.add("dummy1");
        dummyGrantTypes.add("dummy2");

        applicationRegistrationRequest.setGrantTypes(dummyGrantTypes);

        startTenantFlow();

        mockApplicationManagementService = mock(ApplicationManagementService.class);
        DCRDataHolder dcrDataHolder = DCRDataHolder.getInstance();
        dcrDataHolder.setApplicationManagementService(mockApplicationManagementService);

        try {
            dcrmService.registerApplication(applicationRegistrationRequest);
        } catch (IdentityException ex) {
            assertEquals(ex.getErrorCode(), DCRMConstants.ErrorMessages.FAILED_TO_REGISTER_SP.toString());
            return;
        }
        fail("Expected exception IdentityException not thrown by registerApplication method");
    }

    @DataProvider(name = "RedirectAndGrantTypeProvider")
    public Object[][] getListSizeAndGrantType() {

        List<String> redirectUri1 = new ArrayList<>();
        return new Object[][]{
                {"implicit", redirectUri1},
                {"authorization_code", redirectUri1},
        };
    }

    @Test(dataProvider = "RedirectAndGrantTypeProvider")
    public void registerApplicationTestWithSPWithFailCallback(String grantTypeVal, List<String> redirectUri)
            throws Exception {

        mockApplicationManagementService = mock(ApplicationManagementService.class);

        Whitebox.setInternalState(dcrmService, "oAuthAdminService", mockOAuthAdminService);

        startTenantFlow();

        dummyGrantTypes.add(grantTypeVal);
        applicationRegistrationRequest.setGrantTypes(dummyGrantTypes);

        String grantType = StringUtils.join(applicationRegistrationRequest.getGrantTypes(), " ");

        ServiceProvider serviceProvider = new ServiceProvider();

        DCRDataHolder dcrDataHolder = DCRDataHolder.getInstance();
        dcrDataHolder.setApplicationManagementService(mockApplicationManagementService);
        when(mockApplicationManagementService.getServiceProvider(dummyClientName, dummyTenantDomain)).thenReturn
                (null, serviceProvider);

        applicationRegistrationRequest.setRedirectUris(redirectUri);

        OAuthConsumerAppDTO oAuthConsumerApp = new OAuthConsumerAppDTO();
        oAuthConsumerApp.setApplicationName(dummyClientName);

        oAuthConsumerApp.setGrantTypes(grantType);
        oAuthConsumerApp.setOAuthVersion(OAUTH_VERSION);

        when(mockOAuthAdminService
                .getOAuthApplicationDataByAppName(dummyClientName)).thenReturn(oAuthConsumerApp);

        try {
            dcrmService.registerApplication(applicationRegistrationRequest);
        } catch (IdentityException ex) {
            assertEquals(ex.getErrorCode(), DCRMConstants.ErrorMessages.BAD_REQUEST_INVALID_INPUT.toString());
            return;
        }
        fail("Expected exception IdentityException not thrown by registerApplication method");
    }

    @DataProvider(name = "redirectUriProvider")
    public Object[][] getReDirecturi() {

        List<String> redirectUri1 = new ArrayList<>();
        redirectUri1.add("redirectUri1");
        List<String> redirectUri2 = new ArrayList<>();
        redirectUri2.add("redirectUri1");
        redirectUri2.add("redirectUri1");
        return new Object[][]{
                {redirectUri1},
                {redirectUri2}
        };
    }

    @Test(dataProvider = "redirectUriProvider")
    public void registerApplicationTestWithSP(List<String> redirectUri) throws Exception {

        mockApplicationManagementService = mock(ApplicationManagementService.class);

        Whitebox.setInternalState(dcrmService, "oAuthAdminService", mockOAuthAdminService);

        startTenantFlow();

        dummyGrantTypes.add("implicit");
        applicationRegistrationRequest.setGrantTypes(dummyGrantTypes);

        String grantType = StringUtils.join(applicationRegistrationRequest.getGrantTypes(), " ");

        ServiceProvider serviceProvider = new ServiceProvider();

        DCRDataHolder dcrDataHolder = DCRDataHolder.getInstance();
        dcrDataHolder.setApplicationManagementService(mockApplicationManagementService);
        when(mockApplicationManagementService.getServiceProvider(dummyClientName, dummyTenantDomain)).thenReturn
                (null, serviceProvider);

        applicationRegistrationRequest.setRedirectUris(redirectUri);

        OAuthConsumerAppDTO oAuthConsumerApp = new OAuthConsumerAppDTO();
        oAuthConsumerApp.setApplicationName(dummyClientName);

        oAuthConsumerApp.setGrantTypes(grantType);
        oAuthConsumerApp.setOAuthVersion(OAUTH_VERSION);

        when(mockOAuthAdminService
                .getOAuthApplicationDataByAppName(dummyClientName)).thenReturn(oAuthConsumerApp);

        Application application = dcrmService.registerApplication(applicationRegistrationRequest);
        assertEquals(application.getClient_name(), dummyClientName);
    }

    @Test
    public void testRegisterApplicationWithInvalidSPName() throws Exception {

        mockApplicationManagementService = mock(ApplicationManagementService.class);

        Whitebox.setInternalState(dcrmService, "oAuthAdminService", mockOAuthAdminService);

        startTenantFlow();

        dummyGrantTypes.add("implicit");
        applicationRegistrationRequest.setGrantTypes(dummyGrantTypes);
        applicationRegistrationRequest.setClientName(dummyInvalidClientName);

        try {
            dcrmService.registerApplication(applicationRegistrationRequest);
        } catch (IdentityException ex) {
            assertEquals(ex.getErrorCode(), DCRMConstants.ErrorMessages.BAD_REQUEST_INVALID_SP_NAME.toString());
            return;
        }
        fail("Expected exception IdentityException not thrown by registerApplication method");
    }

    @Test(dataProvider = "redirectUriProvider")
    public void registerApplicationTestWithDeleteCreatedSP(List<String> redirectUri) throws Exception {

        mockStatic(IdentityProviderManager.class);

        mockApplicationManagementService = mock(ApplicationManagementService.class);

        Whitebox.setInternalState(dcrmService, "oAuthAdminService", mockOAuthAdminService);

        startTenantFlow();

        dummyGrantTypes.add("implicit");
        applicationRegistrationRequest.setGrantTypes(dummyGrantTypes);

        String grantType = StringUtils.join(applicationRegistrationRequest.getGrantTypes(), " ");

        ServiceProvider serviceProvider = new ServiceProvider();

        DCRDataHolder dcrDataHolder = DCRDataHolder.getInstance();
        dcrDataHolder.setApplicationManagementService(mockApplicationManagementService);
        when(mockApplicationManagementService.getServiceProvider(dummyClientName, dummyTenantDomain)).thenReturn
                (null, serviceProvider);

        applicationRegistrationRequest.setRedirectUris(redirectUri);

        OAuthConsumerAppDTO oAuthConsumerApp = new OAuthConsumerAppDTO();
        oAuthConsumerApp.setApplicationName(dummyClientName);

        oAuthConsumerApp.setGrantTypes(grantType);
        oAuthConsumerApp.setOAuthVersion(OAUTH_VERSION);

        whenNew(OAuthConsumerAppDTO.class).withNoArguments().thenReturn(oAuthConsumerApp);

        doThrow(new IdentityOAuthAdminException("")).when(mockOAuthAdminService)
                .registerOAuthApplicationData(oAuthConsumerApp);

        try {
            dcrmService.registerApplication(applicationRegistrationRequest);
        } catch (IdentityException ex) {
            assertEquals(ex.getErrorCode(), DCRMConstants.ErrorMessages.FAILED_TO_REGISTER_APPLICATION.toString());
            return;
        }
        fail("Expected exception IdentityException not thrown by registerApplication method");
    }

    @Test(dataProvider = "redirectUriProvider")
    public void registerApplicationTestWithFailedToDeleteCreatedSP(List<String> redirectUri) throws Exception {

        mockStatic(IdentityProviderManager.class);

        mockApplicationManagementService = mock(ApplicationManagementService.class);

        Whitebox.setInternalState(dcrmService, "oAuthAdminService", mockOAuthAdminService);

        startTenantFlow();

        dummyGrantTypes.add("implicit");
        applicationRegistrationRequest.setGrantTypes(dummyGrantTypes);

        String grantType = StringUtils.join(applicationRegistrationRequest.getGrantTypes(), " ");

        ServiceProvider serviceProvider = new ServiceProvider();

        DCRDataHolder dcrDataHolder = DCRDataHolder.getInstance();
        dcrDataHolder.setApplicationManagementService(mockApplicationManagementService);
        when(mockApplicationManagementService.getServiceProvider(dummyClientName, dummyTenantDomain)).thenReturn
                (null, serviceProvider);

        applicationRegistrationRequest.setRedirectUris(redirectUri);

        OAuthConsumerAppDTO oAuthConsumerApp = new OAuthConsumerAppDTO();
        oAuthConsumerApp.setApplicationName(dummyClientName);

        oAuthConsumerApp.setGrantTypes(grantType);
        oAuthConsumerApp.setOAuthVersion(OAUTH_VERSION);

        whenNew(OAuthConsumerAppDTO.class).withNoArguments().thenReturn(oAuthConsumerApp);

        doThrow(new IdentityOAuthAdminException("")).when(mockOAuthAdminService)
                .registerOAuthApplicationData(oAuthConsumerApp);
        doThrow(new IdentityApplicationManagementException("")).when(mockApplicationManagementService)
                .deleteApplication(dummyClientName, dummyTenantDomain, dummyUserName);

        try {
            dcrmService.registerApplication(applicationRegistrationRequest);
        } catch (IdentityException ex) {
            assertEquals(ex.getErrorCode(), DCRMConstants.ErrorMessages.FAILED_TO_DELETE_SP.toString());
            return;
        }
        fail("Expected exception IdentityException not thrown by registerApplication method");
    }

    @Test(dataProvider = "redirectUriProvider")
    public void registerApplicationTestWithFailedToUpdateSP(List<String> redirectUri) throws Exception {

        mockApplicationManagementService = mock(ApplicationManagementService.class);

        Whitebox.setInternalState(dcrmService, "oAuthAdminService", mockOAuthAdminService);

        startTenantFlow();

        dummyGrantTypes.add("implicit");
        applicationRegistrationRequest.setGrantTypes(dummyGrantTypes);

        String grantType = StringUtils.join(applicationRegistrationRequest.getGrantTypes(), " ");

        ServiceProvider serviceProvider = new ServiceProvider();
        serviceProvider.setApplicationName(dummyClientName);

        DCRDataHolder dcrDataHolder = DCRDataHolder.getInstance();
        dcrDataHolder.setApplicationManagementService(mockApplicationManagementService);
        when(mockApplicationManagementService.getServiceProvider(dummyClientName, dummyTenantDomain)).thenReturn
                (null, serviceProvider);

        applicationRegistrationRequest.setRedirectUris(redirectUri);

        OAuthConsumerAppDTO oAuthConsumerApp = new OAuthConsumerAppDTO();
        oAuthConsumerApp.setApplicationName(dummyClientName);

        oAuthConsumerApp.setGrantTypes(grantType);
        oAuthConsumerApp.setOAuthVersion(OAUTH_VERSION);
        oAuthConsumerApp.setOauthConsumerKey("dummyConsumerKey");
        oAuthConsumerApp.setUsername(dummyUserName.concat("@").concat(dummyTenantDomain));

        when(mockOAuthAdminService
                .getOAuthApplicationDataByAppName(dummyClientName)).thenReturn(oAuthConsumerApp);
        when(mockOAuthAdminService
                .getOAuthApplicationData("dummyConsumerKey")).thenReturn(oAuthConsumerApp);
        when(mockOAuthAdminService.getAllOAuthApplicationData()).thenReturn(new OAuthConsumerAppDTO[]{oAuthConsumerApp});

        doThrow(new IdentityApplicationManagementException("ehweh")).when(mockApplicationManagementService)
                .updateApplication(serviceProvider, dummyTenantDomain, dummyUserName);
        try {
            dcrmService.registerApplication(applicationRegistrationRequest);
        } catch (IdentityException ex) {
            assertEquals(ex.getErrorCode(), DCRMConstants.ErrorMessages.FAILED_TO_UPDATE_SP.toString());
            return;
        }
        fail("Expected exception IdentityException not thrown by registerApplication method");
    }

    @Test
    public void updateApplicationTestWithException()
            throws DCRMException, IdentityOAuthAdminException, IdentityApplicationManagementException {

        List<String> redirectUri = new ArrayList<>();
        dummyGrantTypes.add("dummyVal");
        redirectUri.add("dummyUri");
        ApplicationUpdateRequest applicationUpdateRequest = mock(ApplicationUpdateRequest.class);
        applicationUpdateRequest.setClientName(dummyClientName);
        applicationUpdateRequest.setGrantTypes(dummyGrantTypes);
        applicationUpdateRequest.setRedirectUris(redirectUri);
        mockApplicationManagementService = mock(ApplicationManagementService.class);

        Whitebox.setInternalState(dcrmService, "oAuthAdminService", mockOAuthAdminService);

        OAuthConsumerAppDTO dto = new OAuthConsumerAppDTO();
        dto.setApplicationName(dummyClientName);
        String dummyClientId = "dummyClientId";
        when(mockOAuthAdminService.getOAuthApplicationData(dummyClientId)).thenReturn(dto);

        ServiceProvider serviceProvider = new ServiceProvider();
        DCRDataHolder dcrDataHolder = DCRDataHolder.getInstance();
        dcrDataHolder.setApplicationManagementService(mockApplicationManagementService);
        when(mockApplicationManagementService.getServiceProvider(dummyClientName, dummyTenantDomain)).thenReturn
                (serviceProvider);
        when(mockOAuthAdminService.getAllOAuthApplicationData()).thenReturn(new OAuthConsumerAppDTO[0]);

        doNothing().when(mockApplicationManagementService).updateApplication(serviceProvider, dummyTenantDomain,
                dummyUserName);

        doThrow(new IdentityOAuthAdminException("")).when(mockOAuthAdminService).updateConsumerApplication(any
                (OAuthConsumerAppDTO.class));

        try {
            startTenantFlow();
            dcrmService.updateApplication(applicationUpdateRequest, dummyClientId);
        } catch (IdentityException ex) {
            assertEquals(ex.getErrorCode(), DCRMConstants.ErrorMessages.FORBIDDEN_UNAUTHORIZED_USER.toString());
            return;
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
        fail("Expected exception IdentityException not thrown by updateApplication method");
    }

    private void startTenantFlow() {
        String carbonHome = Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString();
        System.setProperty(CarbonBaseConstants.CARBON_HOME, carbonHome);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(dummyTenantDomain);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername(dummyUserName);
    }

}
