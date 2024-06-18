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

import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.testng.annotations.BeforeTest;
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
import org.wso2.carbon.identity.oauth.dcr.DCRException;
import org.wso2.carbon.identity.oauth.dcr.internal.DCRDataHolder;
import org.wso2.carbon.identity.oauth.dcr.model.RegistrationRequestProfile;
import org.wso2.carbon.identity.oauth.dcr.model.RegistrationResponseProfile;
import org.wso2.carbon.identity.oauth.dcr.util.DCRMUtils;
import org.wso2.carbon.identity.oauth.dcr.util.ErrorCodes;
import org.wso2.carbon.identity.oauth.dto.OAuthConsumerAppDTO;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.fail;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth10AParams.OAUTH_VERSION;

/**
 * Unit test covering DCRManagementService
 */
public class DCRManagementServiceTest {

    private final String tenantDomain = "dummyTenantDomain";
    private final String userName = "dummyUserName";
    private final String invalidClientName = "dummy@ClientName";
    private final String userID = "dummyUserId";
    private final String consumerkey = "dummyConsumerkey";
    private DCRManagementService dcrManagementService;
    private final List<String> dummyGrantTypes = new ArrayList<>();
    private String applicationName;
    private RegistrationRequestProfile registrationRequestProfile;
    private ApplicationManagementService mockApplicationManagementService;
    private DCRDataHolder dcrDataHolder;

    @BeforeTest
    public void getInstanceTest() {

        dummyGrantTypes.add("code");
        dummyGrantTypes.add("implicit");
        dcrManagementService = DCRManagementService.getInstance();
        assertNotNull(dcrManagementService);
        registrationRequestProfile = new RegistrationRequestProfile();
    }

    @Test
    public void registerOAuthApplicationWithNullExistingSP() {

        registerOAuthApplication();

        mockApplicationManagementService = mock(ApplicationManagementService.class);

        DCRDataHolder dcrDataHolder = DCRDataHolder.getInstance();
        dcrDataHolder.setApplicationManagementService(mockApplicationManagementService);

        assertNotNull(dcrDataHolder, "null DCRDataHolder");

        try {
            dcrManagementService.registerOAuthApplication(registrationRequestProfile);
        } catch (IdentityException ex) {
            assertEquals(ex.getMessage(), "Couldn't create Service Provider Application " + applicationName);
            return;
        }
        fail("Expected IdentityException was not thrown by registerOAuthApplication method");
    }

    @Test
    public void registerOAuthApplicationWithIAMException() throws IdentityApplicationManagementException {

        registerOAuthApplication();
        mockApplicationManagementService = mock(ApplicationManagementService.class);

        DCRDataHolder dcrDataHolder = DCRDataHolder.getInstance();
        dcrDataHolder.setApplicationManagementService(mockApplicationManagementService);

        doThrow(new IdentityApplicationManagementException("")).when(mockApplicationManagementService).
                getServiceProvider(applicationName, tenantDomain);

        try {
            dcrManagementService.registerOAuthApplication(registrationRequestProfile);
        } catch (IdentityException ex) {
            assertEquals(ex.getMessage(), "Error occurred while reading service provider, " + applicationName);
            return;
        }
        fail("Expected IdentityException was not thrown by registerOAuthApplication method");
    }

    @Test
    public void registerOAuthApplicationWithExistingSP() throws IdentityApplicationManagementException {

        registerOAuthApplication();
        mockApplicationManagementService = mock(ApplicationManagementService.class);
        ServiceProvider serviceProvider = new ServiceProvider();
        DCRDataHolder dcrDataHolder = DCRDataHolder.getInstance();
        dcrDataHolder.setApplicationManagementService(mockApplicationManagementService);

        when(mockApplicationManagementService.getServiceProvider(applicationName, tenantDomain)).thenReturn
                (serviceProvider);

        assertNotNull(dcrDataHolder);

        try {
            dcrManagementService.registerOAuthApplication(registrationRequestProfile);
        } catch (IdentityException ex) {
            assertEquals(ex.getMessage(), "Service Provider with name: " + applicationName +
                    " already registered");
            return;
        }
        fail("Expected IdentityException was not thrown by registerOAuthApplication method");
    }

    @Test
    public void registerOAuthApplicationWithInvalidSPName() throws Exception {

        registerOAuthApplication();
        mockApplicationManagementService = mock(ApplicationManagementService.class);
        ServiceProvider serviceProvider = new ServiceProvider();
        DCRDataHolder dcrDataHolder = DCRDataHolder.getInstance();
        dcrDataHolder.setApplicationManagementService(mockApplicationManagementService);
        when(mockApplicationManagementService.getServiceProvider(applicationName, tenantDomain)).thenReturn
                (serviceProvider);
        assertNotNull(dcrDataHolder);
        registrationRequestProfile.setClientName(invalidClientName);

        try {
            dcrManagementService.registerOAuthApplication(registrationRequestProfile);
        } catch (IdentityException ex) {
            assertEquals(ex.getMessage(), "The Application name: " + invalidClientName +
                    " is not valid! It is not adhering to" +
                    " the regex: " + DCRMUtils.getSPValidatorRegex());
            return;
        }
        fail("Expected IdentityException was not thrown by registerOAuthApplication method");
    }

    @Test
    public void registerOAuthApplicationWithNewSPNoRedirectUri() throws Exception {

        registerOAuthApplication();
        registrationRequestProfile.setRedirectUris(new ArrayList<>());
        mockApplicationManagementService = mock(ApplicationManagementService.class);

        DCRDataHolder dcrDataHolder = DCRDataHolder.getInstance();
        dcrDataHolder.setApplicationManagementService(mockApplicationManagementService);
        when(mockApplicationManagementService.getServiceProvider(applicationName, tenantDomain)).thenReturn(null,
                new ServiceProvider());
        try {
            dcrManagementService.registerOAuthApplication(registrationRequestProfile);
        } catch (IdentityException ex) {
            assertEquals(ex.getMessage(), "RedirectUris property must have at least one URI value.");
            return;
        }
        fail("Expected IdentityException was not thrown by registerOAuthApplication method");
    }

    @DataProvider(name = "invalidRedirectUriProvider")
    public Object[][] getRedirecturi() {

        return new Object[][]{
                {new ArrayList<>(Arrays.asList("redirect#Uri1"))},
                {new ArrayList<>(Arrays.asList("redirect#Uri1", "redirect#Uri2"))}
        };
    }

    @Test(dataProvider = "invalidRedirectUriProvider")
    public void registerOAuthApplicationWithNewSPWithFragmentRedirectUri(List<String> redirectUri)
            throws IdentityApplicationManagementException {

        registerOAuthApplication();
        mockApplicationManagementService = mock(ApplicationManagementService.class);

        DCRDataHolder dcrDataHolder = DCRDataHolder.getInstance();
        dcrDataHolder.setApplicationManagementService(mockApplicationManagementService);

        when(mockApplicationManagementService.getServiceProvider(applicationName, tenantDomain)).thenReturn(null,
                new ServiceProvider());

        registrationRequestProfile.setRedirectUris(redirectUri);

        try {
            dcrManagementService.registerOAuthApplication(registrationRequestProfile);
        } catch (IdentityException ex) {
            assertEquals(ex.getMessage(), "Redirect URI: " + redirectUri.get(0) + ", is invalid");
            return;
        }
        fail("Expected IdentityException was not thrown by registerOAuthApplication");
    }

    @DataProvider(name = "serviceProviderData")
    public Object[][] getServiceProviderData() {

        List<String> redirectUri1 = new ArrayList<>();
        List<String> redirectUri2 = new ArrayList<>();
        List<String> redirectUri3 = new ArrayList<>();
        redirectUri2.add("redirectUri1");
        redirectUri3.add("redirectUri1");
        redirectUri3.add("redirectUri2");

        List<String> dummyGrantTypes2 = new ArrayList<>();
        List<String> dummyGrantTypes3 = new ArrayList<>();
        dummyGrantTypes2.add("code");
        dummyGrantTypes3.add("code");
        dummyGrantTypes3.add("implicit");

        String dummyOauthConsumerSecret = "dummyOauthConsumerSecret";
        return new Object[][]{
                {"", redirectUri1, dummyGrantTypes2},
                {dummyOauthConsumerSecret, redirectUri2, dummyGrantTypes2},
                {null, redirectUri3, dummyGrantTypes3}
        };
    }

    @Test(dataProvider = "serviceProviderData")
    public void registerOAuthApplicationWithNewSPWithRedirectUri(String oauthConsumerSecret, List<String> redirectUris,
                                                                 List<String> dummyGrantType) throws Exception {
        registerOAuthApplication();

        mockApplicationManagementService = mock(ApplicationManagementService.class);
        registrationRequestProfile.setGrantTypes(dummyGrantType);

        DCRDataHolder dcrDataHolder = DCRDataHolder.getInstance();
        dcrDataHolder.setApplicationManagementService(mockApplicationManagementService);

        when(mockApplicationManagementService.getServiceProvider(applicationName, tenantDomain)).thenReturn(null,
                new ServiceProvider());

        registrationRequestProfile.setRedirectUris(redirectUris);

        OAuthAdminService mockOAuthAdminService = mock(OAuthAdminService.class);

        OAuthConsumerAppDTO oAuthConsumerApp = new OAuthConsumerAppDTO();
        oAuthConsumerApp.setApplicationName(applicationName);
        oAuthConsumerApp.setOAuthVersion(OAUTH_VERSION);
        oAuthConsumerApp.setCallbackUrl("dummyCallback");

        oAuthConsumerApp.setOauthConsumerSecret(oauthConsumerSecret);
        if (dummyGrantType.size() > 1) {
            oAuthConsumerApp.setGrantTypes(dummyGrantType.get(0) + " " + dummyGrantType.get(1));
        } else if (dummyGrantType.size() == 1) {
            oAuthConsumerApp.setGrantTypes(dummyGrantType.get(0));
        }

        try (MockedConstruction<OAuthAdminService> mockedConstruction = mockConstruction(OAuthAdminService.class,
                (mock, context) -> {
                    when(mock.getOAuthApplicationDataByAppName(applicationName)).thenReturn(oAuthConsumerApp);
                    when(mock.registerAndRetrieveOAuthApplicationData(
                            any(OAuthConsumerAppDTO.class))).thenReturn(oAuthConsumerApp);
                })) {

            RegistrationResponseProfile registrationRqstProfile = dcrManagementService.registerOAuthApplication
                    (registrationRequestProfile);
            assertEquals(registrationRqstProfile.getGrantTypes(), dummyGrantType);
            assertEquals(registrationRqstProfile.getClientName(), applicationName);
        }
    }

    @Test
    public void registerApplicationWithMetaDataValidationError() throws Exception {

        List<String> redirectUri = new ArrayList<>();
        redirectUri.add("redirectUri1");
        registerOAuthApplication();
        registrationRequestProfile.setRedirectUris(redirectUri);
        mockApplicationManagementService = mock(ApplicationManagementService.class);
        DCRDataHolder dcrDataHolder = DCRDataHolder.getInstance();
        dcrDataHolder.setApplicationManagementService(mockApplicationManagementService);

        when(mockApplicationManagementService.getServiceProvider(applicationName, tenantDomain)).thenReturn(null,
                new ServiceProvider());
        try (MockedConstruction<OAuthAdminService> mockedConstruction = mockConstruction(OAuthAdminService.class,
                (mock, context) -> {
                    when(mock.registerAndRetrieveOAuthApplicationData(
                            any(OAuthConsumerAppDTO.class))).thenThrow(IdentityOAuthAdminException.class);
                })) {

            try {
                dcrManagementService.registerOAuthApplication(registrationRequestProfile);
            } catch (IdentityException ex) {
                assertEquals(ex.getErrorCode(), ErrorCodes.META_DATA_VALIDATION_FAILED.toString());
                return;
            }
            fail("Expected IdentityException was not thrown by registerOAuthApplication method");
        }

    }

    @Test
    public void unregisterOAuthApplicationIAMExceptionTest() throws Exception {

        try (MockedStatic<MultitenantUtils> multitenantUtils = mockStatic(MultitenantUtils.class)) {
            applicationName = "dummyApplicationName";
            unRegister(multitenantUtils, applicationName);
            try (MockedConstruction<OAuthAdminService> mockedConstruction = mockConstruction(OAuthAdminService.class,
                    (mock, context) -> {
                        OAuthConsumerAppDTO dto = new OAuthConsumerAppDTO();
                        dto.setApplicationName(applicationName);
                        when(mock.getOAuthApplicationData(consumerkey)).thenReturn(dto);
                    })) {
                doThrow(new IdentityApplicationManagementException("")).when(mockApplicationManagementService)
                        .deleteApplication(applicationName, tenantDomain, userName);

                try {
                    dcrManagementService.unregisterOAuthApplication(userID, applicationName, consumerkey);
                } catch (IdentityException ex) {
                    assertEquals(ex.getMessage(), "Error occurred while removing ServiceProvider for application '"
                            + applicationName + "'");
                    return;
                }
                fail("Expected IdentityException was not thrown by unregisterOAuthApplication method");
            }
        }
    }

    @Test
    public void unregisterOAuthApplicationEmptyApplicationNameTest() throws Exception {

        try (MockedStatic<MultitenantUtils> multitenantUtils = mockStatic(MultitenantUtils.class);) {
            applicationName = "dummyApplicationName";
            unRegister(multitenantUtils, applicationName);
            try (MockedConstruction<OAuthAdminService> mockedConstruction = mockConstruction(OAuthAdminService.class,
                    (mock, context) -> {
                        OAuthConsumerAppDTO dto = new OAuthConsumerAppDTO();
                        dto.setApplicationName(applicationName);
                        when(mock.getOAuthApplicationData(consumerkey)).thenReturn(dto);
                    })) {
                applicationName = "";
                try {
                    dcrManagementService.unregisterOAuthApplication(userID, applicationName, consumerkey);
                } catch (IdentityException ex) {
                    assertEquals(ex.getMessage(),
                            "Username, Application Name and Consumer Key cannot be null or empty");
                    return;
                }
                fail("Expected IdentityException was not thrown by unregisterOAuthApplication method");
            }
        }
    }

    @Test
    public void unregisterOAuthApplicationWithNullSPTest() throws Exception {

        try (MockedStatic<MultitenantUtils> multitenantUtils = mockStatic(MultitenantUtils.class);) {
            applicationName = "dummyApplicationName";
            unRegister(multitenantUtils, applicationName);
            try (MockedConstruction<OAuthAdminService> mockedConstruction = mockConstruction(OAuthAdminService.class,
                    (mock, context) -> {
                        OAuthConsumerAppDTO dto = new OAuthConsumerAppDTO();
                        dto.setApplicationName(applicationName);
                        when(mock.getOAuthApplicationData(consumerkey)).thenReturn(dto);
                    })) {
                when(mockApplicationManagementService.getServiceProvider(applicationName, tenantDomain)).thenReturn(
                        null);
                try {
                    dcrManagementService.unregisterOAuthApplication(userID, applicationName, consumerkey);
                } catch (IdentityException ex) {
                    assertEquals(ex.getMessage(), "Couldn't retrieve Service Provider Application " + applicationName);
                    return;
                }
                fail("Expected IdentityException was not thrown by unregisterOAuthApplication method");
            }
        }
    }

    private void unRegister(MockedStatic<MultitenantUtils> multitenantUtils, String applicationName) throws Exception {

        startTenantFlow();
        mockApplicationManagementService = mock(ApplicationManagementService.class);
        ServiceProvider serviceProvider = new ServiceProvider();
        dcrDataHolder = DCRDataHolder.getInstance();
        dcrDataHolder.setApplicationManagementService(mockApplicationManagementService);

        when(mockApplicationManagementService.getServiceProvider(applicationName, tenantDomain)).thenReturn(
                serviceProvider);
        multitenantUtils.when(() -> MultitenantUtils.getTenantDomain(userID)).thenReturn(tenantDomain);
        multitenantUtils.when(() -> MultitenantUtils.getTenantAwareUsername(userID)).thenReturn(userName);
    }

    private void registerOAuthApplication() {

        String clientName = "dummyClientName";
        registrationRequestProfile.setClientName(clientName);
        String ownerName = "dummyOwner";
        registrationRequestProfile.setOwner(ownerName);
        registrationRequestProfile.setGrantTypes(dummyGrantTypes);
        registrationRequestProfile.setTenantDomain(tenantDomain);
        applicationName = registrationRequestProfile.getOwner() + "_" + registrationRequestProfile
                .getClientName();

        startTenantFlow();
    }

    @DataProvider(name = "oauthApplicationDataProvider")
    public Object[][] getExceptionInstanceType() {

        ServiceProvider serviceProvider = new ServiceProvider();
        return new Object[][]{
                {serviceProvider, true},
                {null, false}
        };
    }

    @Test(dataProvider = "oauthApplicationDataProvider")
    public void oAuthApplicationAvailableTest(Object serviceProvider, boolean expected) throws Exception {

        startTenantFlow();
        String dummyApplicationName = "dummyApplicationName";
        mockApplicationManagementService = mock(ApplicationManagementService.class);
        DCRDataHolder dcrDataHolder = DCRDataHolder.getInstance();
        dcrDataHolder.setApplicationManagementService(mockApplicationManagementService);

        when(mockApplicationManagementService.getServiceProvider(dummyApplicationName,
                tenantDomain)).
                thenReturn((ServiceProvider) serviceProvider);
        assertEquals(dcrManagementService.isOAuthApplicationAvailable(dummyApplicationName), expected);
    }

    @Test
    public void oAuthApplicationAvailableExceptionTest() throws Exception {

        startTenantFlow();
        mockApplicationManagementService = mock(ApplicationManagementService.class);
        DCRDataHolder dcrDataHolder = DCRDataHolder.getInstance();
        dcrDataHolder.setApplicationManagementService(mockApplicationManagementService);

        doThrow(new IdentityApplicationManagementException("")).when(mockApplicationManagementService).
                getServiceProvider(applicationName, tenantDomain);

        try {
            dcrManagementService.isOAuthApplicationAvailable(applicationName);
        } catch (DCRException ex) {
            assertEquals(ex.getMessage(), "Error occurred while retrieving information of OAuthApp " + applicationName);
            return;
        }
        fail("Expected IdentityException was not thrown by isOAuthApplicationAvailable method");
    }

    private void startTenantFlow() {

        String carbonHome = Paths.get(System.getProperty("user.dir"), "target").toString();
        System.setProperty(CarbonBaseConstants.CARBON_HOME, carbonHome);
        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(tenantDomain);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername(userName);
    }
}
