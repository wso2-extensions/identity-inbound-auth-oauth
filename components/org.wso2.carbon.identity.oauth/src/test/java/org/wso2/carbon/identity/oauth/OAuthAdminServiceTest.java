package org.wso2.carbon.identity.oauth;

import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.engine.AxisConfiguration;
import org.apache.commons.lang.StringUtils;
import org.mockito.Matchers;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.internal.util.reflection.Whitebox;
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
import org.wso2.carbon.utils.ConfigurationContextService;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.io.File;

import static org.powermock.api.mockito.PowerMockito.doNothing;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;


@PowerMockIgnore({"javax.net.*", "javax.security.*", "javax.crypto.*"})
/*@PrepareForTest({CarbonContext.class, IdentityUtil.class, MultitenantUtils.class, OAuthAppDAO.class,
                 OAuthAdminService.class, OAuthServerConfiguration.class,
                 IdentityCoreServiceComponent.class, ConfigurationContextService.class})*/
@PrepareForTest({OAuthAdminService.class, IdentityCoreServiceComponent.class, ConfigurationContextService.class})
public class OAuthAdminServiceTest extends PowerMockIdentityBaseTest {

    private static final String CONSUMER_KEY = "consumer:key";
    private static final String CONSUMER_SECRET = "consumer:secret";

    @Mock
    private RealmConfiguration realmConfiguration;
    @Mock
    private RealmService realmService;
    @Mock
    private UserRealm userRealm;
    @Mock
    private UserStoreManager userStoreManager;
    @Mock
    private OAuthAppDAO oAtuhAppDAO;
    @Mock
    private ConfigurationContext configurationContext;
    @Mock
    private ConfigurationContextService configurationContextService;

    @Mock
    private AxisConfiguration axisConfiguration;

    @BeforeMethod
    public void setUp() throws Exception {

        MockitoAnnotations.initMocks(this);
        System.setProperty("carbon.home",
                System.getProperty("user.dir") + File.separator + "src" + File.separator + "test"
                        + File.separator + "resources");

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


        whenNew(OAuthAppDAO.class).withNoArguments().thenReturn(oAtuhAppDAO);
        when(oAtuhAppDAO.addOAuthConsumer("admin", -1234, "PRIMARY")).thenReturn(new String[]{"consumer:key",
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

        whenNew(OAuthAppDAO.class).withNoArguments().thenReturn(oAtuhAppDAO);
        OAuthAppDO oAuthAppDO = new OAuthAppDO();
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        oAuthAppDO.setApplicationName("testapp1");
        oAuthAppDO.setUser(authenticatedUser);
        authenticatedUser.setUserName(userName);
        when(oAtuhAppDAO.getOAuthConsumerAppsOfUser(userName, -1234)).thenReturn(new OAuthAppDO[]{oAuthAppDO});
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
        return new Object[][]{{OAuthConstants.OAuthVersions.VERSION_2, "admin"},
                {OAuthConstants.OAuthVersions.VERSION_2, null},
                {null, "admin"}
        };
    }

    @Test(dataProvider = "getRegisterOAuthApplicationData")
    public void testRegisterOAuthApplicationData(String oauthVersion, String userName) throws Exception {


        initConfigsAndRealm();

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
        oAuthConsumerAppDTO.setOauthConsumerKey(CONSUMER_KEY);
        oAuthConsumerAppDTO.setOauthConsumerSecret(CONSUMER_SECRET);
        oAuthConsumerAppDTO.setOAuthVersion(oauthVersion);

        whenNew(OAuthAppDAO.class).withNoArguments().thenReturn(oAtuhAppDAO);
        doNothing().when(oAtuhAppDAO).addOAuthApplication(Matchers.any(OAuthAppDO.class));

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
        String tenantAwareUserName = username;
        int tenantId = MultitenantConstants.SUPER_TENANT_ID;

        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain("carbon.super");
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantId(tenantId);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername(username);

        //mockStatic(MultitenantUtils.class);
        //when(MultitenantUtils.getTenantAwareUsername(Matchers.anyString())).thenReturn(tenantAwareUserName);
        OAuthAppDO app = getDummyOAuthApp(username);
        when(oAtuhAppDAO.getOAuthConsumerAppsOfUser(tenantAwareUserName, tenantId)).thenReturn(new OAuthAppDO[]{app});
        whenNew(OAuthAppDAO.class).withAnyArguments().thenReturn(oAtuhAppDAO);

        OAuthAdminService oAuthAdminService = new OAuthAdminService();
        OAuthConsumerAppDTO[] oAuthConsumerApps = oAuthAdminService.getAllOAuthApplicationData();
        Assert.assertTrue((oAuthConsumerApps.length == 1), "OAuth consumer application count should be one.");
        Assert.assertEquals(oAuthConsumerApps[0].getApplicationName(), app.getApplicationName(), "Application Name should be" +
                " as same as the given application name in the app data object.");
    }

    @Test(expectedExceptions = IdentityOAuthAdminException.class)
    public void testGetAllOAuthApplicationDataException() throws Exception {

        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain("carbon.super");
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantId(-1234);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername(null);

        whenNew(OAuthAppDAO.class).withAnyArguments().thenReturn(oAtuhAppDAO);

        OAuthAdminService oAuthAdminService = new OAuthAdminService();
        oAuthAdminService.getAllOAuthApplicationData();
    }

    @Test
    public void testGetOAuthApplicationData() throws Exception {

        String consumerKey = "some-consumer-key";

        OAuthAppDO app = getDummyOAuthApp("some-user-name");
        when(oAtuhAppDAO.getAppInformation(consumerKey)).thenReturn(app);
        whenNew(OAuthAppDAO.class).withAnyArguments().thenReturn(oAtuhAppDAO);

        OAuthAdminService oAuthAdminService = new OAuthAdminService();
        OAuthConsumerAppDTO oAuthConsumerApp = oAuthAdminService.getOAuthApplicationData(consumerKey);
        Assert.assertEquals(oAuthConsumerApp.getApplicationName(), app.getApplicationName(), "Application name should be " +
                "same as the application name in app data object.");
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
                when(oAtuhAppDAO.getAppInformation(consumerKey)).thenThrow(InvalidOAuthClientException.class);
                break;
            case "IdentityOAuth2Exception":
                when(oAtuhAppDAO.getAppInformation(consumerKey)).thenThrow(IdentityOAuth2Exception.class);
        }
        whenNew(OAuthAppDAO.class).withAnyArguments().thenReturn(oAtuhAppDAO);

        OAuthAdminService oAuthAdminService = new OAuthAdminService();
        oAuthAdminService.getOAuthApplicationData(consumerKey);
    }


    @Test
    public void testGetOAuthApplicationDataByAppName() throws Exception {

        String appName = "some-app-name";

        // Create oauth application data.
        OAuthAppDO app = getDummyOAuthApp("some-user-name");
        when(oAtuhAppDAO.getAppInformationByAppName(appName)).thenReturn(app);
        whenNew(OAuthAppDAO.class).withAnyArguments().thenReturn(oAtuhAppDAO);

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
                when(oAtuhAppDAO.getAppInformationByAppName(appName)).thenThrow(InvalidOAuthClientException.class);
                break;
            case "IdentityOAuth2Exception":
                when(oAtuhAppDAO.getAppInformationByAppName(appName)).thenThrow(IdentityOAuth2Exception.class);
        }
        whenNew(OAuthAppDAO.class).withAnyArguments().thenReturn(oAtuhAppDAO);

        OAuthAdminService oAuthAdminService = new OAuthAdminService();
        oAuthAdminService.getOAuthApplicationDataByAppName(appName);
    }

    private OAuthAppDO getDummyOAuthApp(String username) {

        // / Create oauth application data.
        OAuthAppDO app = new OAuthAppDO();
        app.setApplicationName("some-application-name");
        app.setCallbackUrl("http://call-back-url.com");
        app.setOauthConsumerKey("some-consumer-key");
        app.setOauthConsumerSecret("some-consumer-secret");
        app.setOauthVersion("some-oauth-version");
        app.setGrantTypes("some-grant-types");
        // Create authenticated user.
        AuthenticatedUser user = new AuthenticatedUser();
        user.setUserStoreDomain(UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME);
        user.setUserName(username);
        // Set authenticated user to the app data object.
        app.setUser(user);
        app.setPkceMandatory(false);
        app.setPkceSupportPlain(false);
        app.setUserAccessTokenExpiryTime(1500000);
        app.setApplicationAccessTokenExpiryTime(2000000);
        app.setRefreshTokenExpiryTime(3000000);
        return app;
    }

    @Test
    public void testUpdateConsumerApplication() throws Exception {

    }

    @Test
    public void testGetOauthApplicationState() throws Exception {

    }

    @Test
    public void testUpdateConsumerAppState() throws Exception {

    }

    @Test
    public void testUpdateOauthSecretKey() throws Exception {

      /*  initConfigsAndRealm();
        OAuthAdminService oAuthAdminService = new OAuthAdminService();
        oAuthAdminService.updateOauthSecretKey(CONSUMER_KEY);*/
    }

    @Test
    public void testRemoveOAuthApplicationData() throws Exception {

    }
}