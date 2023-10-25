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

package org.wso2.carbon.identity.oauth;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.engine.AxisConfiguration;
import org.apache.commons.lang.StringUtils;
import org.mockito.Matchers;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.mockito.internal.util.reflection.FieldSetter;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.core.internal.IdentityCoreServiceComponent;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDAO;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.dto.OAuthAppRevocationRequestDTO;
import org.wso2.carbon.identity.oauth.dto.OAuthConsumerAppDTO;
import org.wso2.carbon.identity.oauth.dto.OAuthRevocationResponseDTO;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.TestConstants;
import org.wso2.carbon.identity.oauth2.dao.AccessTokenDAO;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.dao.TokenManagementDAOImpl;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.api.Tenant;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.ConfigurationContextService;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.io.File;
import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.UUID;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.doNothing;
import static org.powermock.api.mockito.PowerMockito.doThrow;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.spy;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;
import static org.powermock.reflect.Whitebox.invokeMethod;

@PowerMockIgnore({"javax.net.*", "javax.security.*", "javax.crypto.*"})
@PrepareForTest({OAuthAdminServiceImpl.class, IdentityCoreServiceComponent.class, ConfigurationContextService.class,
        OAuthUtil.class, OAuthAppDAO.class, OAuth2Util.class, OAuthComponentServiceHolder.class,
        IdentityUtil.class})
public class OAuthAdminServiceImplTest extends PowerMockIdentityBaseTest {

    private static final String CONSUMER_KEY = "consumer:key";
    private static final String CONSUMER_SECRET = "consumer:secret";
    private static final String UPDATED_CONSUMER_SECRET = "updated:consumer:secret";
    private static final String INBOUND_AUTH2_TYPE = "oauth2";

    @Mock
    private RealmConfiguration realmConfiguration;
    @Mock
    private RealmService realmService;
    @Mock
    private UserRealm userRealm;
    @Mock
    private UserStoreManager userStoreManager;
    @Mock
    private OAuthAppDAO oAuthAppDAO;
    @Mock
    private ConfigurationContext configurationContext;
    @Mock
    private AxisConfiguration axisConfiguration;
    @Mock
    private TenantManager tenantManager;
    @Mock
    Tenant mockTenant;
    @Mock
    AbstractUserStoreManager mockAbstractUserStoreManager;
    @Mock
    OAuthComponentServiceHolder mockOAuthComponentServiceHolder;

    @Mock
    ObjectMapper objectMapper;

    @BeforeMethod
    public void setUp() throws Exception {

        MockitoAnnotations.initMocks(this);
        System.setProperty("carbon.home",
                System.getProperty("user.dir") + File.separator + "src" + File.separator + "test"
                        + File.separator + "resources");

        initConfigsAndRealm();
        IdentityTenantUtil.setRealmService(realmService);
        when(realmService.getTenantManager()).thenReturn(tenantManager);
        when(realmService.getBootstrapRealmConfiguration()).thenReturn(realmConfiguration);
    }

    private void initConfigsAndRealm() throws Exception {
        IdentityCoreServiceComponent identityCoreServiceComponent = new IdentityCoreServiceComponent();
        ConfigurationContextService configurationContextService = new ConfigurationContextService
                (configurationContext, null);
        FieldSetter.setField(identityCoreServiceComponent, identityCoreServiceComponent.getClass().
                getDeclaredField("configurationContextService"), configurationContextService);
        when(configurationContext.getAxisConfiguration()).thenReturn(axisConfiguration);


        IdentityTenantUtil.setRealmService(realmService);
        when(realmService.getBootstrapRealmConfiguration()).thenReturn(realmConfiguration);


        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);

    }

    @Test
    public void testRegisterOAuthConsumer() throws Exception {

        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain("carbon.super");
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantId(-1234);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername("admin");

        IdentityTenantUtil.setRealmService(realmService);
        when(realmService.getBootstrapRealmConfiguration()).thenReturn(realmConfiguration);


        whenNew(OAuthAppDAO.class).withNoArguments().thenReturn(oAuthAppDAO);
        when(oAuthAppDAO.addOAuthConsumer("admin", -1234, "PRIMARY")).thenReturn(new String[]{"consumer:key",
                "consumer:secret"});
        OAuthAdminServiceImpl oAuthAdminServiceImpl = new OAuthAdminServiceImpl();
        String[] keySecret = oAuthAdminServiceImpl.registerOAuthConsumer();

        Assert.assertNotNull(keySecret);
        Assert.assertEquals(keySecret.length, 2);
        Assert.assertEquals(keySecret[0], CONSUMER_KEY);
        Assert.assertEquals(keySecret[1], CONSUMER_SECRET);
    }

    @DataProvider(name = "getDataForAllOAuthApplicationData")
    public Object[][] getDataForAllOAuthApplicationData() {
        return new Object[][]{{"admin"}, {null}};
    }

    @Test(dataProvider = "getDataForAllOAuthApplicationData")
    public void testGetAllOAuthApplicationData(String userName) throws Exception {

        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain("carbon.super");
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantId(-1234);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername(userName);

        mockUserstore();

        whenNew(OAuthAppDAO.class).withNoArguments().thenReturn(oAuthAppDAO);
        OAuthAppDO oAuthAppDO = new OAuthAppDO();
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        oAuthAppDO.setApplicationName("testapp1");
        oAuthAppDO.setUser(authenticatedUser);
        authenticatedUser.setUserName(userName);
        when(oAuthAppDAO.getOAuthConsumerAppsOfUser(userName, -1234)).thenReturn(new OAuthAppDO[]{oAuthAppDO});
        OAuthAdminServiceImpl oAuthAdminServiceImpl = new OAuthAdminServiceImpl();
        try {
            OAuthConsumerAppDTO[] allOAuthApplicationData =
                    oAuthAdminServiceImpl.getAllOAuthApplicationData();
            Assert.assertNotNull(allOAuthApplicationData);
            Assert.assertEquals(allOAuthApplicationData.length, 1);
            Assert.assertEquals(allOAuthApplicationData[0].getApplicationName(), "testapp1");
        } catch (IdentityOAuthAdminException allOAuthApplicationData) {
            Assert.assertEquals(allOAuthApplicationData.getMessage(),
                    "User not logged in to get all registered OAuth Applications.");
        }
    }

    @DataProvider(name = "getRegisterOAuthApplicationData")
    public Object[][] getRegisterOAuthApplicationData() {

        return new String[][]{{OAuthConstants.OAuthVersions.VERSION_2, "admin", null, null},
                {OAuthConstants.OAuthVersions.VERSION_2, "admin", CONSUMER_KEY, CONSUMER_SECRET},
                {OAuthConstants.OAuthVersions.VERSION_2, "admin", CONSUMER_KEY, null},
                {OAuthConstants.OAuthVersions.VERSION_2, "admin", null, CONSUMER_SECRET},
                {null, "admin", CONSUMER_KEY, CONSUMER_SECRET}
        };
    }

    @Test(dataProvider = "getRegisterOAuthApplicationData")
    public void testRegisterOAuthApplicationData(String oauthVersion, String userName, String consumerKey, String
            consumerSecret) throws Exception {

        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain("carbon.super");
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantId(-1234);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername(userName);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setUserRealm(userRealm);

        OAuthAdminServiceImpl oAuthAdminServiceImpl = new OAuthAdminServiceImpl();
        OAuthConsumerAppDTO oAuthConsumerAppDTO = new OAuthConsumerAppDTO();
        oAuthConsumerAppDTO.setApplicationName("SAMPLE_APP1");
        oAuthConsumerAppDTO.setCallbackUrl("http://localhost:8080/acsUrl");
        oAuthConsumerAppDTO.setApplicationAccessTokenExpiryTime(1234585);
        oAuthConsumerAppDTO.setGrantTypes("");
        oAuthConsumerAppDTO.setUsername(userName);
        oAuthConsumerAppDTO.setOauthConsumerKey(consumerKey);
        oAuthConsumerAppDTO.setOauthConsumerSecret(consumerSecret);
        oAuthConsumerAppDTO.setOAuthVersion(oauthVersion);
        oAuthConsumerAppDTO.setRenewRefreshTokenEnabled("true");

        whenNew(OAuthAppDAO.class).withNoArguments().thenReturn(oAuthAppDAO);
        doNothing().when(oAuthAppDAO).addOAuthApplication(Matchers.any(OAuthAppDO.class));

        mockUserstore();

        try {
            oAuthAdminServiceImpl.registerOAuthApplicationData(oAuthConsumerAppDTO);
        } catch (IdentityOAuthAdminException e) {
            if (StringUtils.isBlank(userName)) {
                Assert.assertEquals("No authenticated user found. Failed to register OAuth App", e.getMessage());
                return;
            }
            Assert.fail("Error while registering OAuth APP");
        }
    }


    @Test
    public void testGetAllOAuthApplicationData() throws Exception {

        String username = "Moana";
        int tenantId = MultitenantConstants.SUPER_TENANT_ID;

        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain("carbon.super");
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantId(tenantId);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername(username);

        OAuthAppDO app = buildDummyOAuthAppDO(username);
        when(oAuthAppDAO.getOAuthConsumerAppsOfUser(username, tenantId)).thenReturn(new OAuthAppDO[]{app});
        whenNew(OAuthAppDAO.class).withAnyArguments().thenReturn(oAuthAppDAO);

        OAuthAdminServiceImpl oAuthAdminServiceImpl = new OAuthAdminServiceImpl();
        OAuthConsumerAppDTO[] oAuthConsumerApps = oAuthAdminServiceImpl.getAllOAuthApplicationData();
        Assert.assertTrue((oAuthConsumerApps.length == 1), "OAuth consumer application count should be one.");
        assertAllAttributesOfConsumerAppDTO(oAuthConsumerApps[0], app);
    }

    @Test(expectedExceptions = IdentityOAuthAdminException.class)
    public void testGetAllOAuthApplicationDataException() throws Exception {

        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain("carbon.super");
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantId(-1234);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername(null);

        whenNew(OAuthAppDAO.class).withAnyArguments().thenReturn(oAuthAppDAO);

        mockUserstore();

        OAuthAdminServiceImpl oAuthAdminServiceImpl = new OAuthAdminServiceImpl();
        oAuthAdminServiceImpl.getAllOAuthApplicationData();
    }

    @Test
    public void testGetOAuthApplicationData() throws Exception {

        String consumerKey = "some-consumer-key";

        OAuthAppDO app = buildDummyOAuthAppDO("some-user-name");
        when(oAuthAppDAO.getAppInformation(consumerKey)).thenReturn(app);
        whenNew(OAuthAppDAO.class).withAnyArguments().thenReturn(oAuthAppDAO);

        OAuthAdminServiceImpl oAuthAdminServiceImpl = new OAuthAdminServiceImpl();
        OAuthConsumerAppDTO oAuthConsumerApp = oAuthAdminServiceImpl.getOAuthApplicationData(consumerKey);
        assertAllAttributesOfConsumerAppDTO(oAuthConsumerApp, app);
    }

    private void assertAllAttributesOfConsumerAppDTO(OAuthConsumerAppDTO consumerAppDTO, OAuthAppDO appDO) {

        Assert.assertEquals(consumerAppDTO.getApplicationName(), appDO.getApplicationName());
        Assert.assertEquals(consumerAppDTO.getOauthConsumerKey(), appDO.getOauthConsumerKey());
        Assert.assertEquals(consumerAppDTO.getOauthConsumerSecret(), appDO.getOauthConsumerSecret());
        Assert.assertEquals(consumerAppDTO.getCallbackUrl(), appDO.getCallbackUrl());
        Assert.assertEquals(consumerAppDTO.getOAuthVersion(), appDO.getOauthVersion());
        Assert.assertEquals(consumerAppDTO.getUsername(), appDO.getUser().toString());
        Assert.assertEquals(consumerAppDTO.getGrantTypes(), appDO.getGrantTypes());
        Assert.assertEquals(consumerAppDTO.getScopeValidators(), appDO.getScopeValidators());
        Assert.assertEquals(consumerAppDTO.getPkceSupportPlain(), appDO.isPkceSupportPlain());
        Assert.assertEquals(consumerAppDTO.getPkceMandatory(), appDO.isPkceMandatory());
        Assert.assertEquals(consumerAppDTO.getState(), appDO.getState());
        Assert.assertEquals(consumerAppDTO.getUserAccessTokenExpiryTime(), appDO.getUserAccessTokenExpiryTime());
        Assert.assertEquals(consumerAppDTO.getApplicationAccessTokenExpiryTime(),
                appDO.getApplicationAccessTokenExpiryTime());
        Assert.assertEquals(consumerAppDTO.getRefreshTokenExpiryTime(), appDO.getRefreshTokenExpiryTime());

        assertArrayEquals(consumerAppDTO.getAudiences(), appDO.getAudiences());

        Assert.assertEquals(consumerAppDTO.isRequestObjectSignatureValidationEnabled(),
                appDO.isRequestObjectSignatureValidationEnabled());
        Assert.assertEquals(consumerAppDTO.isIdTokenEncryptionEnabled(), appDO.isIdTokenEncryptionEnabled());
        Assert.assertEquals(consumerAppDTO.getIdTokenEncryptionAlgorithm(), appDO.getIdTokenEncryptionAlgorithm());
        Assert.assertEquals(consumerAppDTO.getIdTokenEncryptionMethod(), appDO.getIdTokenEncryptionMethod());
        Assert.assertEquals(consumerAppDTO.getBackChannelLogoutUrl(), appDO.getBackChannelLogoutUrl());
        Assert.assertEquals(consumerAppDTO.getIdTokenExpiryTime(), appDO.getIdTokenExpiryTime());
        Assert.assertEquals(consumerAppDTO.getFrontchannelLogoutUrl(), appDO.getFrontchannelLogoutUrl());
        Assert.assertEquals(consumerAppDTO.isBypassClientCredentials(), appDO.isBypassClientCredentials());
        Assert.assertEquals(consumerAppDTO.getRenewRefreshTokenEnabled(), appDO.getRenewRefreshTokenEnabled());
    }

    private void assertArrayEquals(String[] audiences, String[] audiencesToCompare) {
        List<String> list1 = new ArrayList<>(Arrays.asList(audiences));
        List<String> list2 = new ArrayList<>(Arrays.asList(audiencesToCompare));
        list1.removeAll(list2);
        Assert.assertTrue(list1.isEmpty());
    }

    @DataProvider(name = "getAppInformationExceptions")
    public Object[][] getAppInformationExceptions() {
        return new Object[][]{{"InvalidOAuthClientException"}, {"IdentityOAuth2Exception"}};
    }

    @Test(dataProvider = "getAppInformationExceptions", expectedExceptions = IdentityOAuthAdminException.class)
    public void testGetOAuthApplicationDataException(String exception) throws Exception {

        String consumerKey = "invalid_consumer_key";

        whenNew(OAuthAppDAO.class).withAnyArguments().thenReturn(oAuthAppDAO);
        switch (exception) {
            case "InvalidOAuthClientException":
                when(oAuthAppDAO.getAppInformation(consumerKey)).thenThrow(InvalidOAuthClientException.class);
                break;
            case "IdentityOAuth2Exception":
                when(oAuthAppDAO.getAppInformation(consumerKey)).thenThrow(IdentityOAuth2Exception.class);
        }

        OAuthAdminServiceImpl oAuthAdminServiceImpl = new OAuthAdminServiceImpl();
        oAuthAdminServiceImpl.getOAuthApplicationData(consumerKey);
    }

    @Test
    public void testGetOAuthApplicationDataByAppName() throws Exception {

        String appName = "some-app-name";

        // Create oauth application data.
        OAuthAppDO app = buildDummyOAuthAppDO("some-user-name");
        when(oAuthAppDAO.getAppInformationByAppName(appName)).thenReturn(app);
        whenNew(OAuthAppDAO.class).withAnyArguments().thenReturn(oAuthAppDAO);

        OAuthAdminServiceImpl oAuthAdminServiceImpl = new OAuthAdminServiceImpl();
        OAuthConsumerAppDTO oAuthConsumerApp = oAuthAdminServiceImpl.getOAuthApplicationDataByAppName(appName);
        Assert.assertEquals(oAuthConsumerApp.getApplicationName(), app.getApplicationName(),
                "Application name should be same as the application name in app data object.");
    }

    @Test(dataProvider = "getAppInformationExceptions", expectedExceptions = IdentityOAuthAdminException.class)
    public void testGetOAuthApplicationDataByAppNameException(String exception) throws Exception {

        String appName = "some-app-name";

        switch (exception) {
            case "InvalidOAuthClientException":
                when(oAuthAppDAO.getAppInformationByAppName(appName)).thenThrow(InvalidOAuthClientException.class);
                break;
            case "IdentityOAuth2Exception":
                when(oAuthAppDAO.getAppInformationByAppName(appName)).thenThrow(IdentityOAuth2Exception.class);
        }
        whenNew(OAuthAppDAO.class).withAnyArguments().thenReturn(oAuthAppDAO);

        OAuthAdminServiceImpl oAuthAdminServiceImpl = new OAuthAdminServiceImpl();
        oAuthAdminServiceImpl.getOAuthApplicationDataByAppName(appName);
    }

    private OAuthAppDO buildDummyOAuthAppDO(String ownerUserName) {

        // / Create oauth application data.
        OAuthAppDO app = new OAuthAppDO();
        app.setApplicationName("some-application-name");
        app.setCallbackUrl("http://call-back-url.com");
        app.setOauthConsumerKey("some-consumer-key");
        app.setOauthConsumerSecret("some-consumer-secret");
        app.setOauthVersion("some-oauth-version");
        app.setGrantTypes("some-grant-types");
        app.setScopeValidators(new String[]{"some-scope-valiator-1", "some-scope-valiator-2"});
        // Create authenticated user.
        AuthenticatedUser user = new AuthenticatedUser();
        user.setUserStoreDomain(UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME);
        user.setUserName(ownerUserName);
        user.setTenantDomain("wso2.com");
        // Set authenticated user to the app data object.
        app.setUser(user);
        app.setPkceMandatory(true);
        app.setPkceSupportPlain(true);
        app.setUserAccessTokenExpiryTime(1500);
        app.setApplicationAccessTokenExpiryTime(2000);
        app.setRefreshTokenExpiryTime(3000);

        app.setState("ACTIVE");
        app.setAudiences(new String[] { "audience1", "audience2"});
        app.setRequestObjectSignatureValidationEnabled(true);
        app.setIdTokenEncryptionEnabled(true);
        app.setIdTokenEncryptionAlgorithm("RSA-11");
        app.setIdTokenEncryptionMethod("Method1");
        app.setBackChannelLogoutUrl("https://localhost/app/logout");
        app.setIdTokenExpiryTime(8000);
        app.setFrontchannelLogoutUrl("https://localhost/app/frontchannellogout");
        app.setBypassClientCredentials(true);
        app.setRenewRefreshTokenEnabled("false");

        return app;
    }

    @DataProvider(name = "getUpdateConsumerAppTestData")
    public Object[][] getUpdateConsumerAppTestData() {

        return new Object[][]{
                // Logged In user , App Owner in Request , App Owner in request exists, Excepted App Owner after update
                {"admin@carbon.super", "H2/new-app-owner@carbon.super", false, "original-app-owner@wso2.com"},
                {"admin@carbon.super", "H2/new-app-owner@carbon.super", true, "H2/new-app-owner@carbon.super"},
                {"admin@wso2.com", "H2/new-app-owner@wso2.com", false, "original-app-owner@wso2.com"},
                {"admin@wso2.com", "H2/new-app-owner@wso2.com", true, "H2/new-app-owner@wso2.com"}
        };
    }

    private AuthenticatedUser buildUser(String fullQualifiedUsername) {
        String tenantDomain = MultitenantUtils.getTenantDomain(fullQualifiedUsername);
        String userStoreDomain = UserCoreUtil.extractDomainFromName(fullQualifiedUsername);

        String domainFreeName = UserCoreUtil.removeDomainFromName(fullQualifiedUsername);
        String username = MultitenantUtils.getTenantAwareUsername(domainFreeName);

        AuthenticatedUser user = new AuthenticatedUser();
        user.setUserName(username);
        user.setUserStoreDomain(userStoreDomain);
        user.setTenantDomain(tenantDomain);

        return user;
    }

    @Test(dataProvider = "getUpdateConsumerAppTestData")
    public void testUpdateConsumerApplication(String loggedInUsername,
                                              String appOwnerInRequest,
                                              boolean appOwnerInRequestExists,
                                              String expectedAppOwnerAfterUpdate) throws Exception {

        AuthenticatedUser loggedInUser = buildUser(loggedInUsername);

        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(loggedInUser.getTenantDomain());
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantId(
                IdentityTenantUtil.getTenantId(loggedInUser.getTenantDomain()));
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername(loggedInUser.getUserName());
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setUserRealm(userRealm);


        AuthenticatedUser appOwner = buildUser(appOwnerInRequest);
        String tenantAwareUsernameOfAppOwner =
                MultitenantUtils.getTenantAwareUsername(appOwner.toFullQualifiedUsername());

        when(userStoreManager.isExistingUser(tenantAwareUsernameOfAppOwner)).thenReturn(appOwnerInRequestExists);

        String consumerKey = UUID.randomUUID().toString();
        OAuthAppDO app = buildDummyOAuthAppDO("original-app-owner");
        AuthenticatedUser originalOwner = app.getAppOwner();

        OAuthAppDAO oAuthAppDAOMock = PowerMockito.spy(new OAuthAppDAO());
        OAuthAppDO oAuthAppDO = new OAuthAppDO();
        PowerMockito.doReturn(true).when(oAuthAppDAOMock, "validateUserForOwnerUpdate", oAuthAppDO);
        when(oAuthAppDAO.getAppInformation(consumerKey)).thenReturn(app);
        whenNew(OAuthAppDAO.class).withAnyArguments().thenReturn(oAuthAppDAO);

        OAuthAdminServiceImpl oAuthAdminServiceImpl = new OAuthAdminServiceImpl();
        OAuthConsumerAppDTO consumerAppDTO = new OAuthConsumerAppDTO();
        consumerAppDTO.setApplicationName("new-application-name");
        consumerAppDTO.setCallbackUrl("http://new-call-back-url.com");
        consumerAppDTO.setOauthConsumerKey(consumerKey);
        consumerAppDTO.setOauthConsumerSecret("some-consumer-secret");
        consumerAppDTO.setOAuthVersion("new-oauth-version");
        consumerAppDTO.setUsername(appOwner.toFullQualifiedUsername());

        mockOAuthComponentServiceHolder();

        String tenantDomain = MultitenantUtils.getTenantDomain(appOwnerInRequest);
        String userStoreDomain = UserCoreUtil.extractDomainFromName(appOwnerInRequest);
        String domainFreeName = UserCoreUtil.removeDomainFromName(appOwnerInRequest);
        String username = MultitenantUtils.getTenantAwareUsername(domainFreeName);

        org.wso2.carbon.user.core.common.User user = new org.wso2.carbon.user.core.common.User();
        user.setUsername(username);
        user.setTenantDomain(tenantDomain);
        user.setUserStoreDomain(userStoreDomain);
        Mockito.when(mockAbstractUserStoreManager.getUser(any(), anyString())).thenReturn(user);
        Mockito.when(mockAbstractUserStoreManager.isExistingUser(anyString())).thenReturn(appOwnerInRequestExists);

        mockStatic(IdentityUtil.class);
        when(IdentityUtil.isUserStoreCaseSensitive(anyString(), anyInt())).thenReturn(true);
        when(IdentityUtil.addDomainToName(anyString(), anyString())).thenCallRealMethod();

        oAuthAdminServiceImpl.updateConsumerApplication(consumerAppDTO);
        OAuthConsumerAppDTO updatedOAuthConsumerApp = oAuthAdminServiceImpl.getOAuthApplicationData(consumerKey);
        Assert.assertEquals(updatedOAuthConsumerApp.getApplicationName(), consumerAppDTO.getApplicationName(),
                "Updated Application name should be same as the application name in consumerAppDTO data object.");
        Assert.assertEquals(updatedOAuthConsumerApp.getCallbackUrl(), consumerAppDTO.getCallbackUrl(),
                "Updated Application callbackUrl should be same as the callbackUrl in consumerAppDTO data object.");

        if (appOwnerInRequestExists) {
            // Application update should change the app owner if the app owner sent in the request is a valid user.
            Assert.assertNotEquals(updatedOAuthConsumerApp.getUsername(), originalOwner.toFullQualifiedUsername());
        }
        Assert.assertEquals(updatedOAuthConsumerApp.getUsername(), expectedAppOwnerAfterUpdate);
    }

    @Test
    public void testGetOauthApplicationState() throws Exception {

    }

    @Test
    public void testUpdateConsumerAppState() throws Exception {

    }

    @Test
    public void testUpdateOauthSecretKey() throws Exception {

        mockStatic(OAuthUtil.class);
        when(OAuthUtil.getRandomNumberSecure()).thenReturn(UPDATED_CONSUMER_SECRET);
        when(OAuthUtil.buildConsumerAppDTO(any())).thenCallRealMethod();

        OAuthAdminServiceImpl oAuthAdminServiceImpl = spy(new OAuthAdminServiceImpl());
        doNothing().when(oAuthAdminServiceImpl, "updateAppAndRevokeTokensAndAuthzCodes", anyString(),
                Matchers.any(Properties.class));

        whenNew(OAuthAppDAO.class).withNoArguments().thenReturn(oAuthAppDAO);

        OAuthAppDO oAuthAppDO = new OAuthAppDO();
        oAuthAppDO.setOauthConsumerKey(CONSUMER_KEY);
        oAuthAppDO.setOauthConsumerSecret(UPDATED_CONSUMER_SECRET);

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName("test_user");
        oAuthAppDO.setAppOwner(authenticatedUser);

        when(oAuthAppDAO.getAppInformation(CONSUMER_KEY)).thenReturn(oAuthAppDO);

        OAuthConsumerAppDTO oAuthConsumerAppDTO;
        oAuthConsumerAppDTO = oAuthAdminServiceImpl.updateAndRetrieveOauthSecretKey(CONSUMER_KEY);

        Assert.assertEquals(oAuthConsumerAppDTO.getOauthConsumerSecret(), UPDATED_CONSUMER_SECRET);
    }

    @Test(expectedExceptions = IdentityOAuthAdminException.class)
    public void testUpdateOauthSecretKeyWithException() throws Exception {

        mockStatic(OAuthUtil.class);
        when(OAuthUtil.getRandomNumberSecure()).thenReturn(UPDATED_CONSUMER_SECRET);
        OAuthAdminServiceImpl oAuthAdminServiceImpl = spy(new OAuthAdminServiceImpl());
        doThrow(new IdentityOAuthAdminException("Error while regenerating consumer secret")).when(oAuthAdminServiceImpl,
                "updateAppAndRevokeTokensAndAuthzCodes", anyString(), Matchers.any(Properties.class));
        oAuthAdminServiceImpl.updateAndRetrieveOauthSecretKey(CONSUMER_KEY);
    }

    @Test
    public void testRemoveOAuthApplicationData() throws Exception {

    }

    @Test
    public void testGetSupportedTokens() throws Exception {

        OAuthAdminServiceImpl oAuthAdminService = new OAuthAdminServiceImpl();

        List<String> supportedTokenTypes = oAuthAdminService.getSupportedTokenTypes();
        Assert.assertEquals(supportedTokenTypes.size(), 2);
        Assert.assertTrue(supportedTokenTypes.contains("Default"));
        Assert.assertTrue(supportedTokenTypes.contains("JWT"));

        // Calling again to test that the same list is returned again.
        List<String> supportedTokenTypesCall2 = oAuthAdminService.getSupportedTokenTypes();
        Assert.assertEquals(supportedTokenTypesCall2.size(), 2);
        Assert.assertTrue(supportedTokenTypesCall2.contains("Default"));
        Assert.assertTrue(supportedTokenTypesCall2.contains("JWT"));
    }

    @Test
    public void testRevokeIssuedTokensByApplication() throws Exception {

        String userId = UUID.randomUUID().toString();
        String consumerKey = UUID.randomUUID().toString();
        String accessToken = UUID.randomUUID().toString();
        String refreshToken = UUID.randomUUID().toString();

        OAuthAppDO oAuthAppDO = new OAuthAppDO();
        oAuthAppDO.setOauthConsumerKey(consumerKey);
        oAuthAppDO.setApplicationName("some-user-name");

        when(oAuthAppDAO.getAppInformation(consumerKey)).thenReturn(oAuthAppDO);
        PowerMockito.whenNew(OAuthAppDAO.class).withNoArguments().thenReturn(oAuthAppDAO);

        AuthenticatedUser user = buildUser("some-user-name");
        user.setUserId(userId);
        user.setFederatedIdPName(TestConstants.LOCAL_IDP);

        OAuthAppRevocationRequestDTO oAuthAppRevocationRequestDTO = new OAuthAppRevocationRequestDTO();
        oAuthAppRevocationRequestDTO.setConsumerKey(consumerKey);

        AccessTokenDO dummyToken = new AccessTokenDO();
        dummyToken.setAccessToken(accessToken);
        dummyToken.setRefreshToken(refreshToken);
        dummyToken.setAuthzUser(user);
        dummyToken.setScope(new String[]{"openid"});
        Set<AccessTokenDO> accessTokenDOSet = new HashSet<>();
        accessTokenDOSet.add(dummyToken);

        OAuthTokenPersistenceFactory tokenPersistenceFactory = OAuthTokenPersistenceFactory.getInstance();

        TokenManagementDAOImpl mockTokenManagementDAOImpl = mock(TokenManagementDAOImpl.class);
        FieldSetter.setField(tokenPersistenceFactory,
                tokenPersistenceFactory.getClass().getDeclaredField("managementDAO"), mockTokenManagementDAOImpl);

        AccessTokenDAO mockAccessTokenDAO = mock(AccessTokenDAO.class);
        FieldSetter.setField(tokenPersistenceFactory,
                tokenPersistenceFactory.getClass().getDeclaredField("tokenDAO"), mockAccessTokenDAO);


        when(mockAccessTokenDAO.getActiveAcessTokenDataByConsumerKey(anyString()))
                .thenReturn(accessTokenDOSet);
        OAuthRevocationResponseDTO expectedOAuthRevocationResponseDTO = new OAuthRevocationResponseDTO();
        expectedOAuthRevocationResponseDTO.setError(false);

        ApplicationManagementService appMgtService = mock(ApplicationManagementService.class);
        when(appMgtService.getServiceProviderNameByClientId(consumerKey, INBOUND_AUTH2_TYPE, user.getTenantDomain())).
                thenReturn(oAuthAppDO.getApplicationName());
        OAuth2ServiceComponentHolder.setApplicationMgtService(appMgtService);

        OAuthAdminServiceImpl oAuthAdminServiceImpl = spy(new OAuthAdminServiceImpl());
        doNothing().when(oAuthAdminServiceImpl, "triggerPreApplicationTokenRevokeListeners", anyObject());
        doNothing().when(oAuthAdminServiceImpl, "triggerPostApplicationTokenRevokeListeners", anyObject(),
                anyObject(), anyObject());

        OAuthRevocationResponseDTO actualOAuthRevocationResponseDTO = oAuthAdminServiceImpl
                .revokeIssuedTokensByApplication(oAuthAppRevocationRequestDTO);
        Assert.assertEquals(actualOAuthRevocationResponseDTO.isError(), expectedOAuthRevocationResponseDTO.isError());
    }

    @Test
    public void testRevokeIssuedTokensByApplicationWithEmptyConsumerKey() throws Exception {

        OAuthAppRevocationRequestDTO oAuthAppRevocationRequestDTO = new OAuthAppRevocationRequestDTO();
        oAuthAppRevocationRequestDTO.setConsumerKey("");

        OAuthAdminServiceImpl oAuthAdminServiceImpl = spy(new OAuthAdminServiceImpl());
        doNothing().when(oAuthAdminServiceImpl, "triggerPreApplicationTokenRevokeListeners", anyObject());

        OAuthRevocationResponseDTO actualOAuthRevocationResponseDTO = oAuthAdminServiceImpl
                .revokeIssuedTokensByApplication(oAuthAppRevocationRequestDTO);
        Assert.assertEquals(actualOAuthRevocationResponseDTO.getErrorCode(), OAuth2ErrorCodes.INVALID_REQUEST);
    }

    @DataProvider(name = "invalidAudienceDataProvider")
    public Object[][] getInvalidAudiences() {

        return new Object[][]{
                {new String[]{" "}},
                {new String[]{""}},
                {new String[]{null}},
                {new String[]{"duplicate", "duplicate"}},
                {new String[]{null, "", "   ", "duplicate", "duplicate"}}
        };
    }

    @Test(description = "Test validating invalid audiences", dataProvider = "invalidAudienceDataProvider")
    public void testValidateAudiencesWithInvalidAudiences(String[] invalidAudience) {

        OAuthConsumerAppDTO appDTO = new OAuthConsumerAppDTO();
        appDTO.setAudiences(invalidAudience);

        OAuthAdminServiceImpl oAuthAdminService = new OAuthAdminServiceImpl();

        try {
            invokeMethod(oAuthAdminService, "validateAudiences", appDTO);
        } catch (Exception ex) {
            Assert.assertTrue(ex instanceof IdentityOAuthClientException);
            Assert.assertEquals(((IdentityOAuthClientException) ex).getErrorCode(),
                    Error.INVALID_REQUEST.getErrorCode());
        }
    }

    @DataProvider(name = "validAudienceDataProvider")
    public Object[][] getValidAudiences() {

        return new Object[][]{
                {null},
                {new String[0]},
                {new String[]{"audience1"}},
                {new String[]{"audience1", "audience2"}}
        };
    }

    @Test(description = "Test validating invalid audiences", dataProvider = "validAudienceDataProvider")
    public void testValidateAudiencesWithValidAudiences(String[] validaAudience) throws Exception {

        OAuthConsumerAppDTO appDTO = new OAuthConsumerAppDTO();
        appDTO.setAudiences(validaAudience);

        OAuthAdminServiceImpl oAuthAdminService = new OAuthAdminServiceImpl();
        invokeMethod(oAuthAdminService, "validateAudiences", appDTO);
    }

    private void mockUserstore() throws Exception {

        mockOAuthComponentServiceHolder();
        Mockito.when(userStoreManager.isExistingUser(anyString())).thenReturn(true);

        mockStatic(IdentityUtil.class);
        when(IdentityUtil.isUserStoreCaseSensitive(anyString(), anyInt())).thenReturn(true);
    }

    private void mockOAuthComponentServiceHolder() throws Exception {

        mockStatic(OAuthComponentServiceHolder.class);
        Mockito.when(OAuthComponentServiceHolder.getInstance())
                .thenReturn(mockOAuthComponentServiceHolder);
        Mockito.when(mockOAuthComponentServiceHolder.getRealmService()).thenReturn(realmService);
        Mockito.when(tenantManager.getTenant(anyInt())).thenReturn(mockTenant);
        Mockito.when(mockTenant.getAssociatedOrganizationUUID()).thenReturn(null);
        Mockito.when(realmService.getTenantUserRealm(anyInt())).thenReturn(userRealm);
        Mockito.when(userRealm.getUserStoreManager()).thenReturn(mockAbstractUserStoreManager);
    }

    @Test(description = "Test validating invalid token auth methods")
    private void testValidateTokenAuthenticationWithValidAuthentication() throws Exception {

        mockStatic(IdentityUtil.class);
        List<String> tokenEndPointAuthMethods = new ArrayList<>();
        tokenEndPointAuthMethods.add("private_key_jwt");
        tokenEndPointAuthMethods.add("tls_client_auth");
        when(IdentityUtil.getPropertyAsList(anyString())).thenReturn(tokenEndPointAuthMethods);
        OAuthAdminServiceImpl oAuthAdminService = new OAuthAdminServiceImpl();
        invokeMethod(oAuthAdminService, "validateFAPITokenAuthMethods",
                "tls_client_auth");
    }

    @Test(description = "Test validating invalid token auth methods")
    private void testValidateTokenAuthenticationWithInvalidAuthentication() throws Exception {

        mockStatic(IdentityUtil.class);
        List<String> tokenEndPointAuthMethods = new ArrayList<>();
        tokenEndPointAuthMethods.add("private_key_jwt");
        tokenEndPointAuthMethods.add("tls_client_auth");
        when(IdentityUtil.getPropertyAsList(anyString())).thenReturn(tokenEndPointAuthMethods);
        OAuthAdminServiceImpl oAuthAdminService = new OAuthAdminServiceImpl();
        try {
            invokeMethod(oAuthAdminService, "validateFAPITokenAuthMethods",
                    "invalid_auth");
        } catch (Exception ex) {
            Assert.assertTrue(ex instanceof IdentityOAuthClientException);
            Assert.assertEquals(((IdentityOAuthClientException) ex).getErrorCode(),
                    Error.INVALID_REQUEST.getErrorCode());
        }
    }

    @Test(description = "Test validating signature algorithm")
    private void testValidateSignatureAlgorithm() throws Exception {

        mockStatic(IdentityUtil.class);
        List<String> validFAPISignatureAlgorithms = new ArrayList<>();
        validFAPISignatureAlgorithms.add("PS256");
        validFAPISignatureAlgorithms.add("ES256");
        when(IdentityUtil.getPropertyAsList(anyString())).thenReturn(validFAPISignatureAlgorithms);
        OAuthAdminServiceImpl oAuthAdminService = new OAuthAdminServiceImpl();
        invokeMethod(oAuthAdminService, "validateFAPISignatureAlgorithms", "PS256");
    }

    @Test(description = "Test validating signature algorithm with invalid value")
    private void testValidateSignatureAlgorithmWithInvalidValue() throws Exception {

        mockStatic(IdentityUtil.class);
        List<String> validFAPISignatureAlgorithms = new ArrayList<>();
        validFAPISignatureAlgorithms.add("PS256");
        validFAPISignatureAlgorithms.add("ES256");
        when(IdentityUtil.getPropertyAsList(anyString())).thenReturn(validFAPISignatureAlgorithms);
        OAuthAdminServiceImpl oAuthAdminService = new OAuthAdminServiceImpl();
        try {
            invokeMethod(oAuthAdminService, "validateFAPISignatureAlgorithms", "PS256");
        } catch (Exception ex) {
            Assert.assertTrue(ex instanceof IdentityOAuthClientException);
            Assert.assertEquals(((IdentityOAuthClientException) ex).getErrorCode(),
                    Error.INVALID_REQUEST.getErrorCode());
        }
    }

    @Test(description = "Test validating encryption algorithm with invalid value")
    private void testValidateEncryptionAlgorithm() throws Exception {

        OAuthAdminServiceImpl oAuthAdminService = new OAuthAdminServiceImpl();
        try {
            invokeMethod(oAuthAdminService, "validateFAPIEncryptionAlgorithms", "RSA1_5");
        } catch (Exception ex) {
            Assert.assertTrue(ex instanceof IdentityOAuthClientException);
            Assert.assertEquals(((IdentityOAuthClientException) ex).getErrorCode(),
                    Error.INVALID_REQUEST.getErrorCode());
        }
    }

    @DataProvider(name = "validCallbackURIDataProvider")
    public Object[][] getValidCallBackURIs() {

        List<String> callBackURI = new ArrayList<>();
        callBackURI.add("https://localhost:8080/callback");
        callBackURI.add("https://localhost:8080/callback1");
        callBackURI.add("https://localhost:8080/callback2");
        return new Object[][]{{callBackURI}};
    }

    @DataProvider(name = "invalidHostNameDataProvider")
    public Object[][] getInvalidCallBackURIs() {

        List<String> callBackURI = new ArrayList<>();
        callBackURI.add("https://localhost:8080/callback");
        callBackURI.add("https://abc:8080/callback1");
        callBackURI.add("https://localhost:8080/callback2");
        return new Object[][]{ {callBackURI}};
    }
    @Test(description = "Test validating multiple redirect URIs have the same host name when PPId is enabled",
            dataProvider = "validCallbackURIDataProvider")
    private void testValidateRedirectURIForPPID (List<String> callBackURIs) throws Exception {

        OAuthAdminServiceImpl oAuthAdminService = new OAuthAdminServiceImpl();
        invokeMethod(oAuthAdminService, "validateRedirectURIForPPID", callBackURIs);
    }

    @Test(description = "Test validating multiple redirect URIs have the same host name when PPId is enabled",
            dataProvider = "invalidHostNameDataProvider")
    private void testValidateRedirectURIForPPIDWithDifferentHosts(List<String> callBackURIs) throws Exception {

        OAuthAdminServiceImpl oAuthAdminService = new OAuthAdminServiceImpl();
        try {
            invokeMethod(oAuthAdminService, "validateRedirectURIForPPID", callBackURIs);
        } catch (Exception ex) {
            Assert.assertTrue(ex instanceof IdentityOAuthClientException);
            Assert.assertEquals(((IdentityOAuthClientException) ex).getErrorCode(),
                    Error.INVALID_REQUEST.getErrorCode());
        }
    }

    @Test(description = "Test validating schem of sectorIdentifierUri")
    private void testValidateSectorIdentifierUriInvalidScheme() throws Exception {

        OAuthAdminServiceImpl oAuthAdminService = new OAuthAdminServiceImpl();
        List<String> callBackURI = new ArrayList<>();
        callBackURI.add("https://localhost:8080/callback");

        try {
            invokeMethod(oAuthAdminService, "validateSectorIdentifierURI",
                    "http://localhost:8080/callback", callBackURI);
        } catch (Exception ex) {
            Assert.assertTrue(ex instanceof IdentityOAuthClientException);
            Assert.assertEquals(((IdentityOAuthClientException) ex).getErrorCode(),
                    Error.INVALID_REQUEST.getErrorCode());
        }
    }

    @Test(description = "Test validating all callBackURIs are present in sectorIdentifierURI array retrieved")
    private void testValidateSectorIdentifierUri() throws Exception {

        OAuthAdminServiceImpl oAuthAdminService = new OAuthAdminServiceImpl();
        List<String> callBackURI = new ArrayList<>();
        callBackURI.add("https://localhost:8080/callback");
        callBackURI.add("https://localhost:8080/callback/a");

        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getProperty(anyString())).thenReturn("true");
        ObjectMapper mapper = new ObjectMapper();
        ArrayNode arrNode = mapper.createArrayNode();
        arrNode.add("https://localhost:8080/callback");
        arrNode.add("https://localhost:8080/callback/a");
        arrNode.add("https://localhost:8080/callback/b");
        whenNew(ObjectMapper.class).withNoArguments().thenReturn(objectMapper);
        String sectorIdentifierUri = "https://localhost:8080/sectors";
        when(objectMapper.readTree(URI.create(sectorIdentifierUri).toURL())).thenReturn(arrNode);

        invokeMethod(oAuthAdminService, "validateSectorIdentifierURI", sectorIdentifierUri,
                callBackURI);

    }

    @Test(description = "Test validating error if all callBackURIs are not present in " +
            "sectorIdentifierURI array retrieved")
    private void testValidateSectorIdentifierUriWithoutMatchingURLs() throws Exception {

        OAuthAdminServiceImpl oAuthAdminService = new OAuthAdminServiceImpl();
        List<String> callBackURI = new ArrayList<>();
        callBackURI.add("https://localhost:8080/callback");
        callBackURI.add("https://localhost:8080/callback/a");

        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getProperty(anyString())).thenReturn("true");
        ObjectMapper mapper = new ObjectMapper();
        ArrayNode arrNode = mapper.createArrayNode();
        arrNode.add("https://localhost:8080/callback");
        arrNode.add("https://localhost:8080/callback/b");
        whenNew(ObjectMapper.class).withNoArguments().thenReturn(objectMapper);
        String sectorIdentifierUri = "https://localhost:8080/sectors";
        when(objectMapper.readTree(URI.create(sectorIdentifierUri).toURL())).thenReturn(arrNode);
        try {
            invokeMethod(oAuthAdminService, "validateSectorIdentifierURI", sectorIdentifierUri,
                    callBackURI);
        } catch (Exception ex) {
            Assert.assertTrue(ex instanceof IdentityOAuthClientException);
            Assert.assertEquals(((IdentityOAuthClientException) ex).getErrorCode(),
                    Error.INVALID_REQUEST.getErrorCode());
        }
    }

    @Test(description = "Test obtaining url list from regex")
    private void testGetRedirectURIList() throws Exception {

        OAuthAdminServiceImpl oAuthAdminService = new OAuthAdminServiceImpl();

        String callbackURls = "regexp=(http://TestApp.com|http://TestApp.com/a)";
        OAuthConsumerAppDTO appDTO = new OAuthConsumerAppDTO();
        appDTO.setCallbackUrl(callbackURls);
        List<String> redirectURIList = invokeMethod(oAuthAdminService, "getRedirectURIList", appDTO);

        Assert.assertEquals(redirectURIList.size(), 2);
        Assert.assertTrue(redirectURIList.contains("http://TestApp.com"));
        Assert.assertTrue(redirectURIList.contains("http://TestApp.com/a"));

    }
}
