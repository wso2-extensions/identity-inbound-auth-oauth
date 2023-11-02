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
import org.mockito.Mock;
import org.mockito.internal.util.reflection.FieldSetter;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.model.ServiceProviderProperty;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.OAuthAdminService;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dcr.DCRMConstants;
import org.wso2.carbon.identity.oauth.dcr.bean.Application;
import org.wso2.carbon.identity.oauth.dcr.bean.ApplicationRegistrationRequest;
import org.wso2.carbon.identity.oauth.dcr.bean.ApplicationUpdateRequest;
import org.wso2.carbon.identity.oauth.dcr.exception.DCRMClientException;
import org.wso2.carbon.identity.oauth.dcr.exception.DCRMException;
import org.wso2.carbon.identity.oauth.dcr.internal.DCRDataHolder;
import org.wso2.carbon.identity.oauth.dcr.util.DCRConstants;
import org.wso2.carbon.identity.oauth.dcr.util.ErrorCodes;
import org.wso2.carbon.identity.oauth.dto.OAuthConsumerAppDTO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.JWTSignatureValidationUtils;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;

import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.doThrow;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;
import static org.powermock.reflect.Whitebox.invokeMethod;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;
import static org.wso2.carbon.identity.oauth.Error.INVALID_OAUTH_CLIENT;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth10AParams.OAUTH_VERSION;

/**
 * Unit test covering DCRMService
 */
@PrepareForTest({DCRMService.class, ServiceProvider.class, IdentityProviderManager.class,
        OAuth2Util.class, OAuthServerConfiguration.class, JWTSignatureValidationUtils.class, IdentityUtil.class})
public class DCRMServiceTest extends PowerMockTestCase {

    private final String dummyConsumerKey = "dummyConsumerKey";
    private final String dummyClientName = "dummyClientName";
    private final String dummyInvalidClientName = "dummy@ClientName";
    private final List<String> dummyGrantTypes = new ArrayList<>();
    private final String dummyUserName = "dummyUserName";
    private final String dummyTenantDomain = "dummyTenantDomain";
    private final String dummyTokenType = "dummyTokenType";
    private String dummyConsumerSecret = "dummyConsumerSecret";
    private String dummyCallbackUrl = "dummyCallbackUrl";
    private final String dummyTemplateName = "dummyTemplateName";
    private final String dummyBackchannelLogoutUri = "http://backchannel.com/";
    private final String dummyJwskUri = "http://localhost.com/jwks";

    @Mock
    private OAuthConsumerAppDTO dto;

    private DCRMService dcrmService;
    private OAuthAdminService mockOAuthAdminService;
    private ApplicationRegistrationRequest applicationRegistrationRequest;
    private ApplicationManagementService mockApplicationManagementService;
    private OAuthServerConfiguration oAuthServerConfiguration;
    private ApplicationUpdateRequest applicationUpdateRequest;

    private UserRealm mockedUserRealm;
    private AbstractUserStoreManager mockedUserStoreManager;

    @ObjectFactory
    public IObjectFactory getObjectFactory() {

        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }

    @BeforeMethod
    public void setUp() throws Exception {

        mockOAuthAdminService = mock(OAuthAdminService.class);
        applicationRegistrationRequest = new ApplicationRegistrationRequest();
        applicationRegistrationRequest.setClientName(dummyClientName);
        dcrmService = new DCRMService();
        mockApplicationManagementService = mock(ApplicationManagementService.class);
        DCRDataHolder dcrDataHolder = DCRDataHolder.getInstance();
        dcrDataHolder.setApplicationManagementService(mockApplicationManagementService);
        when(mockApplicationManagementService.getServiceProviderByClientId(anyString(), anyString(), anyString()))
                .thenReturn(new ServiceProvider());
        oAuthServerConfiguration = mock(OAuthServerConfiguration.class);
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);
        mockStatic(OAuth2Util.class);

        mockedUserRealm = mock(UserRealm.class);
        mockedUserStoreManager = mock(AbstractUserStoreManager.class);
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
        fail("Expected IdentityException was not thrown by getApplication method");
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
        FieldSetter.setField(dcrmService,
                dcrmService.getClass().getDeclaredField("oAuthAdminService"), mockOAuthAdminService);
        try {
            dcrmService.getApplication(dummyConsumerKey);
        } catch (IdentityException ex) {
            assertEquals(ex.getErrorCode(), DCRMConstants.ErrorMessages.NOT_FOUND_APPLICATION_WITH_ID.toString());
            return;
        }
        fail("Expected IdentityException was not thrown by getApplication method");
    }

    @Test
    public void getApplicationDTOTestWithIOAException() throws Exception {

        doThrow(new IdentityOAuthAdminException("")).when(mockOAuthAdminService)
                .getOAuthApplicationData(dummyConsumerKey);
        when(mockOAuthAdminService.getAllOAuthApplicationData()).thenReturn(new OAuthConsumerAppDTO[0]);
        FieldSetter.setField(dcrmService,
                dcrmService.getClass().getDeclaredField("oAuthAdminService"), mockOAuthAdminService);

        try {
            dcrmService.getApplication(dummyConsumerKey);
        } catch (IdentityException ex) {
            assertEquals(ex.getErrorCode(), DCRMConstants.ErrorMessages.FAILED_TO_GET_APPLICATION_BY_ID.toString());
            return;
        }
        fail("Expected IdentityException was not thrown by getApplication method");
    }

    @Test
    public void getApplicationDTOTestWithIOCException() throws Exception {

        doThrow(new IdentityOAuthAdminException("", new InvalidOAuthClientException(""))).when(mockOAuthAdminService)
                .getOAuthApplicationData(dummyConsumerKey);
        when(mockOAuthAdminService.getAllOAuthApplicationData()).thenReturn(new OAuthConsumerAppDTO[0]);
        FieldSetter.setField(dcrmService,
                dcrmService.getClass().getDeclaredField("oAuthAdminService"), mockOAuthAdminService);

        try {
            dcrmService.getApplication(dummyConsumerKey);
        } catch (IdentityException ex) {
            assertEquals(ex.getErrorCode(), DCRMConstants.ErrorMessages.NOT_FOUND_APPLICATION_WITH_ID.toString());
            return;
        }
        fail("Expected IdentityException was not thrown by getApplication method");
    }

    @Test
    public void getApplicationDTOTestUserUnauthorized() throws Exception {

        startTenantFlow();
        FieldSetter.setField(dcrmService,
                dcrmService.getClass().getDeclaredField("oAuthAdminService"), mockOAuthAdminService);
        when(mockOAuthAdminService.getOAuthApplicationData(dummyConsumerKey)).thenReturn(dto);
        when(dto.getApplicationName()).thenReturn(dummyClientName);

        try {
            startTenantFlow();
            PrivilegedCarbonContext.getThreadLocalCarbonContext().setUserRealm(mockedUserRealm);
            when(mockedUserRealm.getUserStoreManager()).thenReturn(mockedUserStoreManager);
            when(mockedUserStoreManager.isUserInRole(anyString(), anyString())).thenReturn(false);
            dcrmService.getApplication(dummyConsumerKey);
        } catch (IdentityException ex) {
            assertEquals(ex.getErrorCode(), DCRMConstants.ErrorMessages.FORBIDDEN_UNAUTHORIZED_USER.toString());
            return;
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
        fail("Expected IdentityException was not thrown by getApplication method");
    }

    @Test
    public void isUserAuthorizedTestWithIAMException() throws IdentityOAuthAdminException,
            UserStoreException, NoSuchFieldException {

        startTenantFlow();
        FieldSetter.setField(dcrmService,
                dcrmService.getClass().getDeclaredField("oAuthAdminService"), mockOAuthAdminService);
        when(mockOAuthAdminService.getOAuthApplicationData(dummyConsumerKey)).thenReturn(dto);
        when(dto.getApplicationName()).thenReturn(dummyClientName);

        try {
            startTenantFlow();
            PrivilegedCarbonContext.getThreadLocalCarbonContext().setUserRealm(mockedUserRealm);
            when(mockedUserRealm.getUserStoreManager()).thenReturn(mockedUserStoreManager);
            when(mockedUserStoreManager.isUserInRole(anyString(), anyString())).thenThrow
                (new org.wso2.carbon.user.core.UserStoreException(""));
            dcrmService.getApplication(dummyConsumerKey);
        } catch (IdentityException ex) {
            assertEquals(ex.getErrorCode(), DCRMConstants.ErrorMessages.FAILED_TO_GET_APPLICATION_BY_ID.toString());
            return;
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
        fail("Expected IdentityException was not thrown by getApplication method");
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

        when(mockOAuthAdminService.getOAuthApplicationData(dummyConsumerKey)).thenReturn(dto);
        FieldSetter.setField(dcrmService,
                dcrmService.getClass().getDeclaredField("oAuthAdminService"), mockOAuthAdminService);
        try {
            startTenantFlow();
            PrivilegedCarbonContext.getThreadLocalCarbonContext().setUserRealm(mockedUserRealm);
            when(mockedUserRealm.getUserStoreManager()).thenReturn(mockedUserStoreManager);
            when(mockedUserStoreManager.isUserInRole(anyString(), anyString())).thenReturn(true);
            ServiceProvider serviceProvider = new ServiceProvider();
            serviceProvider.setJwksUri("dummyJwksUri");
            when(mockApplicationManagementService.getServiceProvider(anyString(), anyString()))
                    .thenReturn(serviceProvider);
            when(mockApplicationManagementService.getServiceProvider(anyString(), anyString()))
                    .thenReturn(new ServiceProvider());
            Application application = dcrmService.getApplication(dummyConsumerKey);

            assertEquals(application.getClientId(), dummyConsumerKey);
            assertEquals(application.getClientName(), dummyClientName);
            assertEquals(application.getClientSecret(), dummyConsumerSecret);
            assertEquals(application.getRedirectUris().get(0), dummyCallbackUrl);
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
    }

    @Test
    public void validateRequestTenantDomainTestWitInvalidOAuthClientException()
            throws IdentityOAuth2Exception, InvalidOAuthClientException {

        when(OAuth2Util.getTenantDomainOfOauthApp(dummyConsumerKey)).thenThrow(new InvalidOAuthClientException(""));
        try {
            dcrmService.getApplication(dummyConsumerKey);
        } catch (DCRMException ex) {
            assertEquals(ex.getMessage(), String.format(DCRMConstants.ErrorMessages.
                    TENANT_DOMAIN_MISMATCH.getMessage(), dummyConsumerKey));
            return;
        }
        fail("Expected IdentityException was not thrown by getApplication method");
    }

    @Test
    public void validateRequestTenantDomainTestWitIdentityOAuth2Exception()
            throws IdentityOAuth2Exception, InvalidOAuthClientException {

        when(OAuth2Util.getTenantDomainOfOauthApp(dummyConsumerKey)).thenThrow(new IdentityOAuth2Exception(""));
        try {
            dcrmService.getApplication(dummyConsumerKey);
        } catch (DCRMException ex) {
            assertEquals(ex.getMessage(), String.format(DCRMConstants.ErrorMessages.
                    FAILED_TO_VALIDATE_TENANT_DOMAIN.getMessage(), dummyConsumerKey));
            return;
        }
        fail("Expected DCRMException was not thrown by getApplication method");
    }

    @Test
    public void getApplicationByNameTest() throws Exception {

        startTenantFlow();
        OAuthConsumerAppDTO oAuthConsumerApp = new OAuthConsumerAppDTO();
        oAuthConsumerApp.setApplicationName(dummyClientName);
        String dummyConsumerSecret = "dummyConsumerSecret";
        oAuthConsumerApp.setOauthConsumerSecret(dummyConsumerSecret);
        oAuthConsumerApp.setOauthConsumerKey(dummyConsumerKey);
        String dummyCallbackUrl = "dummyCallbackUrl";
        oAuthConsumerApp.setCallbackUrl(dummyCallbackUrl);
        oAuthConsumerApp.setUsername(dummyUserName.concat("@").concat(dummyTenantDomain));

        when(mockApplicationManagementService.getServiceProvider(anyString(), anyString()))
                .thenReturn(new ServiceProvider());
        when(mockOAuthAdminService
                .getOAuthApplicationDataByAppName(dummyClientName)).thenReturn(oAuthConsumerApp);
        FieldSetter.setField(dcrmService,
                dcrmService.getClass().getDeclaredField("oAuthAdminService"), mockOAuthAdminService);
        Application application = dcrmService.getApplicationByName(dummyClientName);

        assertEquals(application.getClientId(), dummyConsumerKey);
        assertEquals(application.getClientName(), dummyClientName);
        assertEquals(application.getClientSecret(), dummyConsumerSecret);
        assertEquals(application.getRedirectUris().get(0), dummyCallbackUrl);
    }

    @Test
    public void getApplicationEmptyClientNameTest() throws DCRMException {

        try {
            dcrmService.getApplicationByName("");
        } catch (IdentityException ex) {
            assertEquals(ex.getErrorCode(), DCRMConstants.ErrorMessages.BAD_REQUEST_INSUFFICIENT_DATA.toString());
            return;
        }
        fail("Expected IdentityException was not thrown by getApplicationByName method");
    }

    @Test
    public void getApplicationNullNameTest() throws Exception {

        startTenantFlow();
        try {
            dcrmService.getApplicationByName(dummyClientName);
        } catch (IdentityException ex) {
            assertEquals(ex.getErrorCode(), DCRMConstants.ErrorMessages.NOT_FOUND_APPLICATION_WITH_NAME.toString());
            return;
        }
        fail("Expected IdentityException was not thrown by getApplicationByName method");
    }

    @Test
    public void getApplicationNameWithInvalidOAuthClientExceptionTest() throws Exception {

        startTenantFlow();
        doThrow(new IdentityOAuthAdminException(INVALID_OAUTH_CLIENT.getErrorCode(),
                "Cannot find a valid OAuth client"))
                .when(mockOAuthAdminService)
                .getOAuthApplicationDataByAppName(dummyClientName);
        FieldSetter.setField(dcrmService,
                dcrmService.getClass().getDeclaredField("oAuthAdminService"), mockOAuthAdminService);
        when(mockApplicationManagementService.getServiceProvider(anyString(), anyString()))
                .thenReturn(new ServiceProvider());
        try {
            dcrmService.getApplicationByName(dummyClientName);
        } catch (IdentityException ex) {
            assertEquals(ex.getErrorCode(),
                    DCRMConstants.ErrorMessages.NOT_FOUND_OAUTH_APPLICATION_WITH_NAME.toString());
            return;
        }
        fail("Expected IdentityException was not thrown by getApplicationByName method");
    }

    @Test
    public void getApplicationByNameUserUnauthorizedTest() throws Exception {

        startTenantFlow();
        FieldSetter.setField(dcrmService,
                dcrmService.getClass().getDeclaredField("oAuthAdminService"), mockOAuthAdminService);
        when(mockApplicationManagementService.getServiceProvider(anyString(), anyString()))
                .thenReturn(new ServiceProvider());
        when(mockOAuthAdminService.getOAuthApplicationDataByAppName(dummyClientName))
                .thenReturn(new OAuthConsumerAppDTO());
        try {
            startTenantFlow();
            PrivilegedCarbonContext.getThreadLocalCarbonContext().setUserRealm(mockedUserRealm);
            when(mockedUserRealm.getUserStoreManager()).thenReturn(mockedUserStoreManager);
            when(mockedUserStoreManager.isUserInRole(anyString(), anyString())).thenReturn(false);
            dcrmService.getApplicationByName(dummyClientName);
        } catch (IdentityException ex) {
            assertEquals(ex.getErrorCode(), DCRMConstants.ErrorMessages.FORBIDDEN_UNAUTHORIZED_USER.toString());
            return;
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
        fail("Expected IdentityException was not thrown by getApplicationByName method");
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
        fail("Expected IdentityException was not thrown by registerApplication method");
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
        fail("Expected IdentityException was not thrown by registerApplication method");
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
        fail("Expected IdentityException was not thrown by registerApplication method");
    }

    @Test
    public void registerApplicationTestWithExistClientId() throws Exception {

        dummyGrantTypes.add("dummy1");
        dummyGrantTypes.add("dummy2");

        applicationRegistrationRequest.setGrantTypes(dummyGrantTypes);
        applicationRegistrationRequest.setConsumerKey(dummyConsumerKey);
        startTenantFlow();
        FieldSetter.setField(dcrmService,
                dcrmService.getClass().getDeclaredField("oAuthAdminService"), mockOAuthAdminService);
        when(mockOAuthAdminService.getOAuthApplicationData(dummyConsumerKey))
                .thenReturn(dto);
        when(dto.getApplicationName()).thenReturn(dummyClientName);

        try {
            dcrmService.registerApplication(applicationRegistrationRequest);
        } catch (IdentityException ex) {
            assertEquals(ex.getErrorCode(), DCRMConstants.ErrorMessages.CONFLICT_EXISTING_CLIENT_ID.toString());
            return;
        }
        fail("Expected IdentityException was not thrown by registerApplication method");
    }

    @DataProvider(name = "RedirectAndGrantTypeProvider")
    public Object[][] getListSizeAndGrantType() {

        return new Object[][]{
                {DCRConstants.GrantTypes.IMPLICIT},
                {DCRConstants.GrantTypes.AUTHORIZATION_CODE},
        };
    }

    @Test(dataProvider = "RedirectAndGrantTypeProvider")
    public void registerApplicationTestWithSPWithFailCallback(String grantTypeVal)
            throws Exception {

        mockApplicationManagementService = mock(ApplicationManagementService.class);

        FieldSetter.setField(dcrmService,
                dcrmService.getClass().getDeclaredField("oAuthAdminService"), mockOAuthAdminService);

        startTenantFlow();

        dummyGrantTypes.add(grantTypeVal);
        applicationRegistrationRequest.setGrantTypes(dummyGrantTypes);

        String grantType = StringUtils.join(applicationRegistrationRequest.getGrantTypes(), " ");

        ServiceProvider serviceProvider = new ServiceProvider();

        DCRDataHolder dcrDataHolder = DCRDataHolder.getInstance();
        dcrDataHolder.setApplicationManagementService(mockApplicationManagementService);
        when(mockApplicationManagementService.getServiceProvider(dummyClientName, dummyTenantDomain)).thenReturn
                (null, serviceProvider);

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
        fail("Expected IdentityException was not thrown by registerApplication method");
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

        FieldSetter.setField(dcrmService,
                dcrmService.getClass().getDeclaredField("oAuthAdminService"), mockOAuthAdminService);

        startTenantFlow();

        dummyGrantTypes.add("implicit");
        applicationRegistrationRequest.setGrantTypes(dummyGrantTypes);
        applicationRegistrationRequest.setConsumerSecret(dummyConsumerSecret);
        applicationRegistrationRequest.setTokenType(dummyTokenType);
        applicationRegistrationRequest.setBackchannelLogoutUri(dummyBackchannelLogoutUri);
        applicationRegistrationRequest.setConsumerKey(dummyConsumerKey);

        String grantType = StringUtils.join(applicationRegistrationRequest.getGrantTypes(), " ");

        ServiceProvider serviceProvider = new ServiceProvider();

        DCRDataHolder dcrDataHolder = DCRDataHolder.getInstance();
        dcrDataHolder.setApplicationManagementService(mockApplicationManagementService);
        when(mockApplicationManagementService.getServiceProvider(dummyClientName, dummyTenantDomain)).thenReturn
                (null, serviceProvider);

        applicationRegistrationRequest.setRedirectUris(redirectUri);

        OAuthConsumerAppDTO oAuthConsumerApp = new OAuthConsumerAppDTO();
        oAuthConsumerApp.setApplicationName(dummyClientName);
        oAuthConsumerApp.setGrantTypes(dummyGrantTypes.get(0));
        oAuthConsumerApp.setOauthConsumerKey(dummyConsumerKey);
        oAuthConsumerApp.setOauthConsumerSecret(dummyConsumerSecret);
        oAuthConsumerApp.setCallbackUrl(redirectUri.get(0));
        oAuthConsumerApp.setGrantTypes(grantType);
        oAuthConsumerApp.setOAuthVersion(OAUTH_VERSION);

        when(mockOAuthAdminService
                .getOAuthApplicationDataByAppName(dummyClientName)).thenReturn(oAuthConsumerApp);
        when(mockOAuthAdminService.registerAndRetrieveOAuthApplicationData(any(OAuthConsumerAppDTO.class)))
                .thenReturn(oAuthConsumerApp);
        OAuthServerConfiguration oAuthServerConfiguration = OAuthServerConfiguration.getInstance();
        assertNotNull(oAuthServerConfiguration);
        when(oAuthServerConfiguration.getClientIdValidationRegex()).thenReturn("[a-zA-Z0-9_]{15,30}");
        String toString =  "Application {\n" +
                "  clientName: " + oAuthConsumerApp.getApplicationName() + "\n" +
                "  clientId: " + oAuthConsumerApp.getOauthConsumerKey() + "\n" +
                "  clientSecret: " + oAuthConsumerApp.getOauthConsumerSecret() + "\n" +
                "  redirectUris: " +  Arrays.asList(oAuthConsumerApp.getCallbackUrl()) + "\n" +
                "  grantTypes: " + Arrays.asList(oAuthConsumerApp.getGrantTypes().split(" ")) + "\n" +
                "}\n";
        Application application = dcrmService.registerApplication(applicationRegistrationRequest);
        assertEquals(application.getClientName(), dummyClientName);
        assertEquals(application.getGrantTypes(), dummyGrantTypes);
        assertEquals(application.toString(), toString);
    }

    @Test
    public void registerApplicationWithFailedToRegisterTest() throws
            IdentityApplicationManagementException, IdentityOAuthAdminException, NoSuchFieldException {

        mockApplicationManagementService = mock(ApplicationManagementService.class);
        FieldSetter.setField(dcrmService,
                dcrmService.getClass().getDeclaredField("oAuthAdminService"), mockOAuthAdminService);
        startTenantFlow();

        List<String> redirectUri = new ArrayList<>();
        redirectUri.add("redirectUri1");
        applicationRegistrationRequest.setRedirectUris(redirectUri);

        ServiceProvider serviceProvider = new ServiceProvider();
        DCRDataHolder dcrDataHolder = DCRDataHolder.getInstance();
        dcrDataHolder.setApplicationManagementService(mockApplicationManagementService);
        when(mockApplicationManagementService.getServiceProvider(dummyClientName, dummyTenantDomain)).thenReturn
                (null, serviceProvider);

        when(mockOAuthAdminService
                .getOAuthApplicationDataByAppName(dummyClientName)).thenReturn(new OAuthConsumerAppDTO());
        when(mockOAuthAdminService.registerAndRetrieveOAuthApplicationData(any(OAuthConsumerAppDTO.class)))
                .thenThrow(IdentityOAuthAdminException.class);

        try {
            dcrmService.registerApplication(applicationRegistrationRequest);
        } catch (IdentityException ex) {
            assertEquals(ex.getErrorCode(), DCRMConstants.ErrorMessages.FAILED_TO_REGISTER_APPLICATION.toString());
            return;
        }
        fail("Expected IdentityException was not thrown by registerApplication method");
    }

    @Test
    public void testRegisterApplicationWithInvalidSPName() throws Exception {

        mockApplicationManagementService = mock(ApplicationManagementService.class);
        FieldSetter.setField(dcrmService,
                dcrmService.getClass().getDeclaredField("oAuthAdminService"), mockOAuthAdminService);
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
        fail("Expected IdentityException was not thrown by registerApplication method");
    }

    @Test(dataProvider = "redirectUriProvider")
    public void registerApplicationTestWithDeleteCreatedSP(List<String> redirectUri) throws Exception {

        mockStatic(IdentityProviderManager.class);

        mockApplicationManagementService = mock(ApplicationManagementService.class);

        FieldSetter.setField(dcrmService,
                dcrmService.getClass().getDeclaredField("oAuthAdminService"), mockOAuthAdminService);
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
        fail("Expected IdentityException was not thrown by registerApplication method");
    }

    @Test(dataProvider = "redirectUriProvider")
    public void registerApplicationTestWithFailedToDeleteCreatedSP(List<String> redirectUri) throws Exception {

        mockStatic(IdentityProviderManager.class);
        mockApplicationManagementService = mock(ApplicationManagementService.class);
        FieldSetter.setField(dcrmService,
                dcrmService.getClass().getDeclaredField("oAuthAdminService"), mockOAuthAdminService);

        startTenantFlow();

        dummyGrantTypes.add(DCRConstants.GrantTypes.IMPLICIT);
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
        fail("Expected IdentityException was not thrown by registerApplication method");
    }

    @Test(dataProvider = "redirectUriProvider")
    public void registerApplicationTestWithFailedToUpdateSPTest(List<String> redirectUri) throws Exception {

        registerApplicationTestWithFailedToUpdateSP();
        applicationRegistrationRequest.setRedirectUris(redirectUri);

        try {
            startTenantFlow();
            PrivilegedCarbonContext.getThreadLocalCarbonContext().setUserRealm(mockedUserRealm);
            when(mockedUserRealm.getUserStoreManager()).thenReturn(mockedUserStoreManager);
            when(mockedUserStoreManager.isUserInRole(anyString(), anyString())).thenReturn(true);
            dcrmService.registerApplication(applicationRegistrationRequest);
        } catch (IdentityException ex) {
            assertEquals(ex.getErrorCode(), DCRMConstants.ErrorMessages.FAILED_TO_UPDATE_SP.toString());
            return;
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
        fail("Expected IdentityException was not thrown by registerApplication method");
    }

    @Test(dataProvider = "redirectUriProvider")
    public void registerApplicationTestWithInvalidSpTemplateNameTest(List<String> redirectUri) throws Exception {

        registerApplicationTestWithFailedToUpdateSP();

        applicationRegistrationRequest.setRedirectUris(redirectUri);
        applicationRegistrationRequest.setSpTemplateName("");

        try {
            dcrmService.registerApplication(applicationRegistrationRequest);
        } catch (IdentityException ex) {
            assertEquals(ex.getErrorCode(),
                    DCRMConstants.ErrorMessages.BAD_REQUEST_INVALID_SP_TEMPLATE_NAME.toString());
            return;
        }
        fail("Expected IdentityException was not thrown by registerApplication method");
    }

    @Test(dataProvider = "redirectUriProvider")
    public void registerApplicationTestWithErrorCreataingSPTenantTest(List<String> redirectUri) throws Exception {

        mockApplicationManagementService = mock(ApplicationManagementService.class);
        FieldSetter.setField(dcrmService,
                dcrmService.getClass().getDeclaredField("oAuthAdminService"), mockOAuthAdminService);
        startTenantFlow();

        dummyGrantTypes.add("implicit");
        applicationRegistrationRequest.setGrantTypes(dummyGrantTypes);

        ServiceProvider serviceProvider = new ServiceProvider();
        DCRDataHolder dcrDataHolder = DCRDataHolder.getInstance();
        dcrDataHolder.setApplicationManagementService(mockApplicationManagementService);
        when(mockApplicationManagementService.getServiceProvider(dummyClientName, dummyTenantDomain))
                .thenReturn(null, serviceProvider);
        applicationRegistrationRequest.setRedirectUris(redirectUri);
        applicationRegistrationRequest.setSpTemplateName(dummyTemplateName);
        whenNew(ServiceProvider.class).withNoArguments().thenReturn
                (serviceProvider);
        when(mockApplicationManagementService.isExistingApplicationTemplate(dummyTemplateName, dummyTenantDomain))
                .thenReturn(true);
        doThrow(new IdentityApplicationManagementException("")).when(mockApplicationManagementService)
                .createApplicationWithTemplate(serviceProvider, dummyTenantDomain, dummyUserName, dummyTemplateName);

        try {
            dcrmService.registerApplication(applicationRegistrationRequest);
        } catch (IdentityException ex) {
            assertEquals(ex.getErrorCode(), ErrorCodes.BAD_REQUEST.toString());
            return;
        }
        fail("Expected IdentityException was not thrown by registerApplication method");
    }

    @Test
    public void isClientIdExistTestWithIdentityOAuthAdminException() throws Exception {

        registerApplicationTestWithFailedToUpdateSP();
        List<String> redirectUri = new ArrayList<>();
        redirectUri.add("redirectUri1");
        applicationRegistrationRequest.setRedirectUris(redirectUri);
        applicationRegistrationRequest.setConsumerKey(dummyConsumerKey);
        OAuthAdminService mockOAuthAdminService = mock(OAuthAdminService.class);
        FieldSetter.setField(dcrmService,
                dcrmService.getClass().getDeclaredField("oAuthAdminService"), mockOAuthAdminService);

        whenNew(OAuthAdminService.class).withNoArguments().thenReturn(mockOAuthAdminService);
        IdentityOAuthAdminException identityOAuthAdminException = mock(IdentityOAuthAdminException.class);
        doThrow(identityOAuthAdminException).when(mockOAuthAdminService).getOAuthApplicationData(dummyConsumerKey);
        try {
            dcrmService.registerApplication(applicationRegistrationRequest);
        } catch (IdentityException ex) {
            assertEquals(ex.getErrorCode(),
                    DCRMConstants.ErrorMessages.FAILED_TO_GET_APPLICATION_BY_ID.toString());
            return;
        }
        fail("Expected IdentityException was not thrown by registerApplication method");
    }

    @Test(dataProvider = "redirectUriProvider")
    public void deleteOAuthApplicationWithoutAssociatedSPwithError(List<String> redirectUri) throws Exception {

        OAuthConsumerAppDTO oAuthConsumerApp = registerApplicationTestWithFailedToUpdateSP();
        applicationRegistrationRequest.setRedirectUris(redirectUri);
        doThrow(new IdentityOAuthAdminException("")).when(mockOAuthAdminService)
                .removeOAuthApplicationData(oAuthConsumerApp.getOauthConsumerKey());
        try {
            startTenantFlow();
            PrivilegedCarbonContext.getThreadLocalCarbonContext().setUserRealm(mockedUserRealm);
            when(mockedUserRealm.getUserStoreManager()).thenReturn(mockedUserStoreManager);
            when(mockedUserStoreManager.isUserInRole(anyString(), anyString())).thenReturn(true);
            dcrmService.registerApplication(applicationRegistrationRequest);
        } catch (IdentityException ex) {
            assertEquals(ex.getMessage(), "Error while deleting the OAuth application with consumer key: " +
                    oAuthConsumerApp.getOauthConsumerKey());
            return;
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
        fail("Expected IdentityException was not thrown by registerApplication method");
    }

    private OAuthConsumerAppDTO registerApplicationTestWithFailedToUpdateSP() throws Exception {

        mockApplicationManagementService = mock(ApplicationManagementService.class);
        FieldSetter.setField(dcrmService,
                dcrmService.getClass().getDeclaredField("oAuthAdminService"), mockOAuthAdminService);

        startTenantFlow();

        dummyGrantTypes.add("implicit");
        applicationRegistrationRequest.setGrantTypes(dummyGrantTypes);
        String grantType = StringUtils.join(applicationRegistrationRequest.getGrantTypes(), " ");

        ServiceProvider serviceProvider = new ServiceProvider();
        DCRDataHolder dcrDataHolder = DCRDataHolder.getInstance();
        dcrDataHolder.setApplicationManagementService(mockApplicationManagementService);
        when(mockApplicationManagementService.getServiceProvider(dummyClientName, dummyTenantDomain)).thenReturn
                (null, serviceProvider);

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
        when(mockOAuthAdminService.getAllOAuthApplicationData())
                .thenReturn(new OAuthConsumerAppDTO[]{oAuthConsumerApp});
        when(mockOAuthAdminService.registerAndRetrieveOAuthApplicationData(any(OAuthConsumerAppDTO.class))).
                thenReturn(oAuthConsumerApp);

        doThrow(new IdentityApplicationManagementException("ehweh")).when(mockApplicationManagementService)
                .updateApplication(serviceProvider, dummyTenantDomain, dummyUserName);
        when(mockApplicationManagementService.
                getServiceProviderNameByClientId(oAuthConsumerApp.getOauthConsumerKey(),
                        DCRMConstants.OAUTH2, dummyTenantDomain))
                .thenReturn(IdentityApplicationConstants.DEFAULT_SP_CONFIG);
        return oAuthConsumerApp;
    }

    @Test(dataProvider = "redirectUriProvider")
    public void updateApplicationTest(List<String> redirectUri1) throws Exception {

        updateApplication();
        applicationUpdateRequest.setRedirectUris(redirectUri1);
        Application application = dcrmService.updateApplication(applicationUpdateRequest, dummyConsumerKey);

        assertEquals(application.getClientId(), dummyConsumerKey);
        assertEquals(application.getClientName(), dummyClientName);
        assertEquals(application.getClientSecret(), dummyConsumerSecret);
    }

    @Test
    public void updateApplicationTestWithFailedToGetSP() throws Exception {

        updateApplication();
        when(mockApplicationManagementService.getServiceProvider(dummyClientName, dummyTenantDomain))
                .thenReturn(null);

        try {
            dcrmService.updateApplication(applicationUpdateRequest, dummyConsumerKey);
        } catch (IdentityException ex) {
            assertEquals(ex.getErrorCode(), DCRMConstants.ErrorMessages.FAILED_TO_GET_SP.toString());
            return;
        }
        fail("Expected IdentityException not thrown by updateApplication method");
    }


    @Test
    public void updateApplicationTestWithInvalidSPName() throws Exception {

        updateApplication();
        applicationUpdateRequest.setClientName(dummyInvalidClientName);

        try {
            dcrmService.updateApplication(applicationUpdateRequest, dummyConsumerKey);
        } catch (IdentityException ex) {
            assertEquals(ex.getErrorCode(), DCRMConstants.ErrorMessages.BAD_REQUEST_INVALID_SP_NAME.toString());
            return;
        }
        fail("Expected IdentityException was not thrown by updateApplication method");
    }

    @Test
    public void updateApplicationTestWithSPAlreadyExist() throws Exception {

        startTenantFlow();
        updateApplication();
        applicationUpdateRequest.setClientName("dummynewClientName");

        ServiceProvider serviceProvider = new ServiceProvider();
        serviceProvider.setApplicationName(dummyClientName);

        DCRDataHolder dcrDataHolder = DCRDataHolder.getInstance();
        dcrDataHolder.setApplicationManagementService(mockApplicationManagementService);
        when(mockApplicationManagementService.getServiceProvider("dummynewClientName", dummyTenantDomain))
                .thenReturn(serviceProvider);

        try {
            dcrmService.updateApplication(applicationUpdateRequest, dummyConsumerKey);
        } catch (IdentityException ex) {
            assertEquals(ex.getErrorCode(), DCRMConstants.ErrorMessages.CONFLICT_EXISTING_APPLICATION.toString());
            return;
        }
        fail("Expected IdentityException was not thrown by updateApplication method");
    }

    @Test
    public void updateApplicationTestWithIOAException() throws Exception {

        dto = updateApplication();
        doThrow(new IdentityOAuthAdminException("")).when(mockOAuthAdminService)
                .updateConsumerApplication(dto);
        try {
            dcrmService.updateApplication(applicationUpdateRequest, dummyConsumerKey);
        } catch (IdentityException ex) {
            assertEquals(ex.getErrorCode(), DCRMConstants.ErrorMessages.FAILED_TO_UPDATE_APPLICATION.toString());
            return;
        }
        fail("Expected IdentityException was not thrown by updateApplication method");
    }

    private OAuthConsumerAppDTO updateApplication()
            throws IdentityOAuthAdminException, IdentityApplicationManagementException, NoSuchFieldException {

        startTenantFlow();
        dummyGrantTypes.add("dummy1");
        dummyGrantTypes.add("dummy2");
        applicationUpdateRequest = new ApplicationUpdateRequest();
        applicationUpdateRequest.setClientName(dummyClientName);
        applicationUpdateRequest.setGrantTypes(dummyGrantTypes);
        applicationUpdateRequest.setTokenType(dummyTokenType);
        applicationUpdateRequest.setBackchannelLogoutUri(dummyBackchannelLogoutUri);

        OAuthConsumerAppDTO dto = new OAuthConsumerAppDTO();
        dto.setApplicationName(dummyClientName);
        dto.setOauthConsumerSecret(dummyConsumerSecret);
        dto.setOauthConsumerKey(dummyConsumerKey);
        dto.setCallbackUrl(dummyCallbackUrl);
        dto.setUsername(dummyUserName.concat("@").concat(dummyTenantDomain));

        when(mockOAuthAdminService.getOAuthApplicationData(dummyConsumerKey)).thenReturn(dto);
        FieldSetter.setField(dcrmService,
                dcrmService.getClass().getDeclaredField("oAuthAdminService"), mockOAuthAdminService);

        ServiceProvider serviceProvider = new ServiceProvider();
        serviceProvider.setApplicationName(dummyClientName);

        DCRDataHolder dcrDataHolder = DCRDataHolder.getInstance();
        dcrDataHolder.setApplicationManagementService(mockApplicationManagementService);
        when(mockApplicationManagementService.getServiceProvider(dummyClientName, dummyTenantDomain))
                .thenReturn(serviceProvider);
        return dto;
    }

    private void startTenantFlow() {

        String carbonHome = Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString();
        System.setProperty(CarbonBaseConstants.CARBON_HOME, carbonHome);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(dummyTenantDomain);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername(dummyUserName);
    }

    @DataProvider(name = "redirectUriWithQueryParamsProvider")
    public Object[][] getRedirectUrisWithQueryParams() {

        List<String> redirectUriList = new ArrayList<>();
        redirectUriList.add("https://wso2.com");
        redirectUriList.add("https://wso2.com?dummy1");
        redirectUriList.add("https://wso2.com?dummy1=1&dummy=2");
        List<String> validCallbackList = new ArrayList<>();
        validCallbackList.add("https://wso2.com");
        validCallbackList.add("https://wso2.com?dummy1");
        validCallbackList.add("https://wso2.com?dummy1=1&dummy=2");
        List<String> invalidCallbackList = new ArrayList<>();
        invalidCallbackList.add("https://wso2.com/");
        invalidCallbackList.add("https://wso2.com/?dummy1");
        invalidCallbackList.add("https://wso2.com/?dummy1=1&dummy=2");
        return new Object[][]{
                {redirectUriList, validCallbackList, invalidCallbackList}
        };
    }

    @Test(dataProvider = "redirectUriWithQueryParamsProvider")
    public void registerApplicationTestWithRedirectURls(List<String> redirectUri, List<String> validCallbackList,
                                                        List<String> invalidCallbackList) throws Exception {

        mockApplicationManagementService = mock(ApplicationManagementService.class);

        FieldSetter.setField(dcrmService,
                dcrmService.getClass().getDeclaredField("oAuthAdminService"), mockOAuthAdminService);

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
        oAuthConsumerApp.setCallbackUrl(OAuthConstants.CALLBACK_URL_REGEXP_PREFIX +
                dcrmService.createRegexPattern(redirectUri));

        when(mockOAuthAdminService
                .getOAuthApplicationDataByAppName(dummyClientName)).thenReturn(oAuthConsumerApp);
        when(mockOAuthAdminService.registerAndRetrieveOAuthApplicationData(any(OAuthConsumerAppDTO.class)))
                .thenReturn(oAuthConsumerApp);

        Application application = dcrmService.registerApplication(applicationRegistrationRequest);
        assertEquals(application.getClientName(), dummyClientName);
        String regexp = application.getRedirectUris().get(0)
                .substring(OAuthConstants.CALLBACK_URL_REGEXP_PREFIX.length());
        for (String validCallback : validCallbackList) {
            assertTrue(validCallback.matches(regexp));
        }
        for (String invalidCallback : invalidCallbackList) {
            assertFalse(invalidCallback.matches(regexp));
        }
    }

    @Test(description = "Test to store service provider properties when defined in a map")
    public void testAddSPProperties() throws Exception {

        ServiceProvider serviceProvider = new ServiceProvider();
        Map<String, Object> spProperties = new HashMap<>();
        spProperties.put(OAuthConstants.IS_THIRD_PARTY_APP, true);
        invokeMethod(dcrmService, "addSPProperties", spProperties, serviceProvider);
        ServiceProviderProperty[] serviceProviderProperties = serviceProvider.getSpProperties();
        boolean propertyExists = Arrays.stream(serviceProviderProperties)
                .anyMatch(property -> property.getName().equals(OAuthConstants.IS_THIRD_PARTY_APP));
        assertTrue(propertyExists);
    }

    @Test(description = "Test SSA signature validation")
    public void testValidateSSASignature() throws IdentityOAuth2Exception {

        String jwtString = "eyJ4NXQiOiJObUptT0dVeE16WmxZak0yWkRSaE5UWmxZVEExWXpkaFpUUmlPV0UwTldJMk0ySm1PVGMxWkEiLCJhb" +
                "GciOiJSUzI1NiJ9.eyJhdF9oYXNoIjoiR2ptOGFsN21FSkRVYjZuN3V1Mi1qUSIsInN1YiI6ImFkbWluQGNhcmJvbi5zdXBlciIs" +
                "ImF1ZCI6WyJhVmdieWhBMVY3TWV0ZW1PNEtrUjlFYnBzOW9hIiwiaHR0cHM6XC9cL2xvY2FsaG9zdDo5NDQzXC9vYXV0aDJcL3Rv" +
                "a2VuIl0sImF6cCI6ImFWZ2J5aEExVjdNZXRlbU80S2tSOUVicHM5b2EiLCJhdXRoX3RpbWUiOjE1MjUyMzYzMzcsImlzcyI6Imh0" +
                "dHBzOlwvXC8xMC4xMDAuOC4yOjk0NDNcL29hdXRoMlwvdG9rZW4iLCJleHAiOjE1MjUyMzk5MzcsImlhdCI6MTUyNTIzNjMzN30" +
                ".DOPv7UHymV3zJJpxxWqbGcrvjY-OOzmdJVUxwHorDlOGABP_X_Krd584rLIbcYFmd8q5wSUuX21wXCLCOXFli1CUC-ZfP0S" +
                "0fJqUZv_ynNo6NTFY9d3-sv0b7QYT-8mnxSmjqqsmDrOcxlD7gcYkkr1pLLQe9ZK2B_lR5KZlMW0";

        String jwks = "OAuth.DCRM.SoftwareStatementJWKS";


        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getProperty(jwks)).thenReturn("https://localhost:9444/oauth2/jwks");
        mockStatic(JWTSignatureValidationUtils.class);
        when(JWTSignatureValidationUtils.validateUsingJWKSUri(any(), anyString())).thenReturn(false);
        try {
            invokeMethod(dcrmService, "validateSSASignature", jwtString);
        } catch (Exception e) {
            Assert.assertTrue(e instanceof DCRMClientException);
            Assert.assertEquals(((DCRMClientException) e).getErrorCode(),
                    DCRMConstants.ErrorCodes.INVALID_SOFTWARE_STATEMENT);
        }
    }
}
