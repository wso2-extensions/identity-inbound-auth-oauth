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

import org.mockito.Matchers;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.base.IdentityValidationException;
import org.wso2.carbon.identity.oauth.OAuthAdminService;
import org.wso2.carbon.identity.oauth.dcr.DCRException;
import org.wso2.carbon.identity.oauth.dcr.internal.DCRDataHolder;
import org.wso2.carbon.identity.oauth.dcr.model.RegistrationRequestProfile;
import org.wso2.carbon.identity.oauth.dcr.model.RegistrationResponseProfile;
import org.wso2.carbon.identity.oauth.dto.OAuthConsumerAppDTO;

import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.whenNew;
import static org.powermock.api.mockito.PowerMockito.doThrow;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.fail;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth10AParams.OAUTH_VERSION;

/**
 * Unit test covering DCRManagementService
 */
@PrepareForTest({DCRManagementService.class})
public class DCRManagementServiceTest extends PowerMockTestCase {

    private DCRManagementService dcrManagementService;

    private List<String> dummyGrantTypes = new ArrayList<>();
    private String tenantDomain = "dummyTenantDomain";
    private String applicationName;

    private RegistrationRequestProfile registrationRequestProfile;
    private ApplicationManagementService mockApplicationManagementService;

    @BeforeTest
    public void getInstanceTest() {

        dummyGrantTypes.add("code");
        dummyGrantTypes.add("implicit");
        dcrManagementService = DCRManagementService.getInstance();
        assertNotNull(dcrManagementService);
        registrationRequestProfile = new RegistrationRequestProfile();
    }

    @Test
    public void registerOAuthApplicationExceptionTest() throws DCRException {

        registerOAuthApplication();

        startTenantFlow();
        try {
            dcrManagementService.registerOAuthApplication(registrationRequestProfile);
        } catch (IllegalStateException ex) {
            assertEquals(ex.getMessage(), "ApplicationManagementService is not initialized properly");
            return;
        }
        fail("Expected exception IdentityException not thrown by registerOAuthApplication");
    }

    @Test
    public void registerOAuthApplicationWithNullExistingSP() throws NoSuchFieldException,
            IllegalAccessException, DCRException, IdentityApplicationManagementException {

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
        fail("Expected exception IdentityException not thrown by registerOAuthApplication");
    }

    @Test
    public void registerOAuthApplicationWithIAMException() throws NoSuchFieldException,
            IllegalAccessException, DCRException, IdentityApplicationManagementException {

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
        fail("Expected exception IdentityException not thrown by registerOAuthApplication");
    }

    @Test
    public void registerOAuthApplicationWithExistingSP() throws NoSuchFieldException,
            IllegalAccessException, DCRException, IdentityApplicationManagementException {

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
        fail("Expected exception IdentityException not thrown by registerOAuthApplication");
    }

    @Test
    public void registerOAuthApplicationWithNewSPNoRedirectUri() throws NoSuchFieldException,
            IllegalAccessException, DCRException, IdentityApplicationManagementException {

        registerOAuthApplication();
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
        fail("Expected exception IdentityException not thrown by registerOAuthApplication");
    }

    @Test
    public void registerOAuthApplicationWithNewSPWithFragmentRedirectUri() throws NoSuchFieldException,
            IllegalAccessException, DCRException, IdentityApplicationManagementException, IdentityValidationException {

        registerOAuthApplication();
        List<String> redirectUris = new ArrayList<>();

        redirectUris.add("wvuv#");

        String redirectUri = redirectUris.get(0);
        mockApplicationManagementService = mock(ApplicationManagementService.class);

        DCRDataHolder dcrDataHolder = DCRDataHolder.getInstance();
        dcrDataHolder.setApplicationManagementService(mockApplicationManagementService);

        when(mockApplicationManagementService.getServiceProvider(applicationName, tenantDomain)).thenReturn(null,
                new ServiceProvider());

        registrationRequestProfile.setRedirectUris(redirectUris);

        try {
            dcrManagementService.registerOAuthApplication(registrationRequestProfile);
        } catch (IdentityException ex) {
            assertEquals(ex.getMessage(), "Redirect URI: " + redirectUri + ", is invalid");
            return;
        }
        fail("Expected exception IdentityException not thrown by registerOAuthApplication");
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

        whenNew(OAuthAdminService.class).withNoArguments().thenReturn(mockOAuthAdminService);

        when(mockOAuthAdminService
                .getOAuthApplicationDataByAppName(applicationName)).thenReturn(oAuthConsumerApp);

        when(mockOAuthAdminService.registerAndRetrieveOAuthApplicationData(
                Matchers.any(OAuthConsumerAppDTO.class))).thenReturn(oAuthConsumerApp);

        RegistrationResponseProfile registrationRqstProfile = dcrManagementService.registerOAuthApplication
                (registrationRequestProfile);
        assertEquals(registrationRqstProfile.getGrantTypes(), dummyGrantType);
        assertEquals(registrationRqstProfile.getClientName(), applicationName);
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

    private void startTenantFlow() {

        String carbonHome = Paths.get(System.getProperty("user.dir"), "target").toString();
        System.setProperty(CarbonBaseConstants.CARBON_HOME, carbonHome);
        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(tenantDomain);
        String userName = "dummyUserName";
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername(userName);
    }
}
