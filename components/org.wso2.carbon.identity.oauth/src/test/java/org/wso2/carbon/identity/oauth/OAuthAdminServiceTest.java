package org.wso2.carbon.identity.oauth;

import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.engine.AxisConfiguration;
import org.apache.commons.lang.StringUtils;
import org.mockito.Matchers;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.internal.util.reflection.Whitebox;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.internal.IdentityCoreServiceComponent;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDAO;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.dto.OAuthConsumerAppDTO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.ConfigurationContextService;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.doNothing;
import static org.powermock.api.mockito.PowerMockito.doThrow;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.spy;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;

@PowerMockIgnore({"javax.net.*", "javax.security.*", "javax.crypto.*"})
@PrepareForTest({OAuthAdminService.class, IdentityCoreServiceComponent.class, ConfigurationContextService.class, OAuthUtil.class,
        OAuthAppDAO.class})
public class OAuthAdminServiceTest extends PowerMockIdentityBaseTest {

    private static final String CONSUMER_KEY = "consumer:key";
    private static final String CONSUMER_SECRET = "consumer:secret";
    private static final String UPDATED_CONSUMER_SECRET = "updated:consumer:secret";

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
        Whitebox.setInternalState(identityCoreServiceComponent, "configurationContextService",
                configurationContextService);
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
        OAuthAdminService oAuthAdminService = new OAuthAdminService();
        String[] keySecret = oAuthAdminService.registerOAuthConsumer();

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

        whenNew(OAuthAppDAO.class).withNoArguments().thenReturn(oAuthAppDAO);
        OAuthAppDO oAuthAppDO = new OAuthAppDO();
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        oAuthAppDO.setApplicationName("testapp1");
        oAuthAppDO.setUser(authenticatedUser);
        authenticatedUser.setUserName(userName);
        when(oAuthAppDAO.getOAuthConsumerAppsOfUser(userName, -1234)).thenReturn(new OAuthAppDO[]{oAuthAppDO});
        OAuthAdminService oAuthAdminService = new OAuthAdminService();
        try {
            OAuthConsumerAppDTO[] allOAuthApplicationData =
                    oAuthAdminService.getAllOAuthApplicationData();
            Assert.assertNotNull(allOAuthApplicationData);
            Assert.assertEquals(allOAuthApplicationData.length, 1);
            Assert.assertEquals(allOAuthApplicationData[0].getApplicationName(), "testapp1");
        } catch (IdentityOAuthAdminException allOAuthApplicationData) {
            Assert.assertEquals(allOAuthApplicationData.getMessage(),
                    "User not logged in to get all registered OAuth Applications");
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

        OAuthAdminService oAuthAdminService = new OAuthAdminService();
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

        try {
            oAuthAdminService.registerOAuthApplicationData(oAuthConsumerAppDTO);
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

        OAuthAdminService oAuthAdminService = new OAuthAdminService();
        OAuthConsumerAppDTO[] oAuthConsumerApps = oAuthAdminService.getAllOAuthApplicationData();
        Assert.assertTrue((oAuthConsumerApps.length == 1), "OAuth consumer application count should be one.");
        assertAllAttributesOfConsumerAppDTO(oAuthConsumerApps[0], app);
    }

    @Test(expectedExceptions = IdentityOAuthAdminException.class)
    public void testGetAllOAuthApplicationDataException() throws Exception {

        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain("carbon.super");
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantId(-1234);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername(null);

        whenNew(OAuthAppDAO.class).withAnyArguments().thenReturn(oAuthAppDAO);

        OAuthAdminService oAuthAdminService = new OAuthAdminService();
        oAuthAdminService.getAllOAuthApplicationData();
    }

    @Test
    public void testGetOAuthApplicationData() throws Exception {

        String consumerKey = "some-consumer-key";

        OAuthAppDO app = buildDummyOAuthAppDO("some-user-name");
        when(oAuthAppDAO.getAppInformation(consumerKey)).thenReturn(app);
        whenNew(OAuthAppDAO.class).withAnyArguments().thenReturn(oAuthAppDAO);

        OAuthAdminService oAuthAdminService = new OAuthAdminService();
        OAuthConsumerAppDTO oAuthConsumerApp = oAuthAdminService.getOAuthApplicationData(consumerKey);
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

        String consumerKey = "some-consumer-key";

        switch (exception) {
            case "InvalidOAuthClientException":
                when(oAuthAppDAO.getAppInformation(consumerKey)).thenThrow(InvalidOAuthClientException.class);
                break;
            case "IdentityOAuth2Exception":
                when(oAuthAppDAO.getAppInformation(consumerKey)).thenThrow(IdentityOAuth2Exception.class);
        }
        whenNew(OAuthAppDAO.class).withAnyArguments().thenReturn(oAuthAppDAO);

        OAuthAdminService oAuthAdminService = new OAuthAdminService();
        oAuthAdminService.getOAuthApplicationData(consumerKey);
    }

    @Test
    public void testGetOAuthApplicationDataByAppName() throws Exception {

        String appName = "some-app-name";

        // Create oauth application data.
        OAuthAppDO app = buildDummyOAuthAppDO("some-user-name");
        when(oAuthAppDAO.getAppInformationByAppName(appName)).thenReturn(app);
        whenNew(OAuthAppDAO.class).withAnyArguments().thenReturn(oAuthAppDAO);

        OAuthAdminService oAuthAdminService = new OAuthAdminService();
        OAuthConsumerAppDTO oAuthConsumerApp = oAuthAdminService.getOAuthApplicationDataByAppName(appName);
        Assert.assertEquals(oAuthConsumerApp.getApplicationName(), app.getApplicationName(), "Application name should be " +
                "same as the application name in app data object.");
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

        OAuthAdminService oAuthAdminService = new OAuthAdminService();
        oAuthAdminService.getOAuthApplicationDataByAppName(appName);
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
                {"admin@carbon.super", "H2/new-app-owner@carbon.super", false, "admin@carbon.super"},
                {"admin@carbon.super", "H2/new-app-owner@carbon.super", true, "H2/new-app-owner@carbon.super"},
                {"admin@wso2.com", "H2/new-app-owner@wso2.com", false, "admin@wso2.com"},
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

        String consumerKey = "some-consumer-key";
        OAuthAppDO app = buildDummyOAuthAppDO("some-user-name");
        AuthenticatedUser originalOwner = app.getAppOwner();

        OAuthAppDAO oAuthAppDAOMock = PowerMockito.spy(new OAuthAppDAO());
        OAuthAppDO oAuthAppDO = new OAuthAppDO();
        PowerMockito.doReturn(true).when(oAuthAppDAOMock, "validateUserForOwnerUpdate", oAuthAppDO);
        when(oAuthAppDAO.getAppInformation(consumerKey)).thenReturn(app);
        whenNew(OAuthAppDAO.class).withAnyArguments().thenReturn(oAuthAppDAO);

        OAuthAdminService oAuthAdminService = new OAuthAdminService();
        OAuthConsumerAppDTO consumerAppDTO = new OAuthConsumerAppDTO();
        consumerAppDTO.setApplicationName("new-application-name");
        consumerAppDTO.setCallbackUrl("http://new-call-back-url.com");
        consumerAppDTO.setOauthConsumerKey("some-consumer-key");
        consumerAppDTO.setOauthConsumerSecret("some-consumer-secret");
        consumerAppDTO.setOAuthVersion("new-oauth-version");


        consumerAppDTO.setUsername(appOwner.toFullQualifiedUsername());
        oAuthAdminService.updateConsumerApplication(consumerAppDTO);
        OAuthConsumerAppDTO updatedOAuthConsumerApp = oAuthAdminService.getOAuthApplicationData(consumerKey);
        Assert.assertEquals(updatedOAuthConsumerApp.getApplicationName(), consumerAppDTO.getApplicationName(),
                "Updated Application name should be same as the application name in consumerAppDTO data object.");
        Assert.assertEquals(updatedOAuthConsumerApp.getCallbackUrl(), consumerAppDTO.getCallbackUrl(),
                "Updated Application callbackUrl should be same as the callbackUrl in consumerAppDTO data object.");

        // Application update should change the app owner.
        Assert.assertNotEquals(updatedOAuthConsumerApp.getUsername(), originalOwner.toFullQualifiedUsername());
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
        when(OAuthUtil.getRandomNumber()).thenReturn(UPDATED_CONSUMER_SECRET);
        OAuthAdminService oAuthAdminService = spy(new OAuthAdminService());
        doNothing().when(oAuthAdminService, "updateAppAndRevokeTokensAndAuthzCodes", anyString(),
                Matchers.any(Properties.class));
        OAuthConsumerAppDTO oAuthConsumerAppDTO;
        oAuthConsumerAppDTO = oAuthAdminService.updateAndRetrieveOauthSecretKey(CONSUMER_KEY);

        Assert.assertEquals(oAuthConsumerAppDTO.getOauthConsumerSecret(), UPDATED_CONSUMER_SECRET);
    }

    @Test(expectedExceptions = IdentityOAuthAdminException.class)
    public void testUpdateOauthSecretKeyWithException() throws Exception {

        mockStatic(OAuthUtil.class);
        when(OAuthUtil.getRandomNumber()).thenReturn(UPDATED_CONSUMER_SECRET);
        OAuthAdminService oAuthAdminService = spy(new OAuthAdminService());
        doThrow(new IdentityOAuthAdminException("Error while regenerating consumer secret")).when(oAuthAdminService,
                "updateAppAndRevokeTokensAndAuthzCodes", anyString(), Matchers.any(Properties.class));
        oAuthAdminService.updateAndRetrieveOauthSecretKey(CONSUMER_KEY);
    }

    @Test
    public void testRemoveOAuthApplicationData() throws Exception {

    }
}