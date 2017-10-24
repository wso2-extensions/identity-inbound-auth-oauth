package org.wso2.carbon.identity.oauth;

import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.engine.AxisConfiguration;
import org.mockito.Matchers;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.mockito.internal.matchers.Any;
import org.mockito.internal.util.reflection.Whitebox;
import org.powermock.api.mockito.PowerMockito;
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
import org.wso2.carbon.identity.oauth.dao.OAuthAppDAO;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.dto.OAuthConsumerAppDTO;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.ConfigurationContextService;

import java.io.File;

import static org.powermock.api.mockito.PowerMockito.doNothing;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;

@PrepareForTest({OAuthAdminService.class, IdentityCoreServiceComponent.class, ConfigurationContextService.class})
public class OAuthAdminServiceTest extends PowerMockIdentityBaseTest {

    private static final String CONSUMER_KEY = "consumer:key";
    private static final String CONSUMER_SECRET = "consumer:secret";

    @Mock
    private RealmConfiguration realmConfiguration ;
    @Mock
    private RealmService realmService ;
    @Mock
    private UserRealm userRealm ;
    @Mock
    private UserStoreManager userStoreManager;
    @Mock
    private OAuthAppDAO oAtuhAppDAO;
    @Mock
    private ConfigurationContext configurationContext;
    @Mock
    private ConfigurationContextService configurationContextService ;

    @Mock
    private AxisConfiguration axisConfiguration;

    @BeforeMethod
    public void setUp() throws Exception {

        MockitoAnnotations.initMocks(this);
        System.setProperty("carbon.home",
                           System.getProperty("user.dir") + File.separator + "src" + File.separator + "test"
                           + File.separator + "resources");

    }

    @Test
    public void testRegisterOAuthConsumer() throws Exception {

        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain("carbon.super");
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantId(-1234);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername("admin");

        whenNew(OAuthAppDAO.class).withNoArguments().thenReturn(oAtuhAppDAO);
        when(oAtuhAppDAO.addOAuthConsumer("admin", -1234, "PRIMARY")).thenReturn(new String[] { "consumer:key",
                                                                                                "consumer:secret" });
        OAuthAdminService oAuthAdminService = new OAuthAdminService();
        String[] keySecret = oAuthAdminService.registerOAuthConsumer();

        Assert.assertNotNull(keySecret);
        Assert.assertEquals(keySecret.length, 2);
        Assert.assertEquals(keySecret[0], CONSUMER_KEY);
        Assert.assertEquals(keySecret[1], CONSUMER_SECRET);
    }

    @DataProvider(name = "getDataForAllOAuthApplicationData")
    public Object[][] getDataForAllOAuthApplicationData() {
        return new Object[][] { { "admin" }, { null } };
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
        when(oAtuhAppDAO.getOAuthConsumerAppsOfUser(userName, -1234)).thenReturn(new OAuthAppDO[] { oAuthAppDO });
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

    @Test
    public void testGetOAuthApplicationData() throws Exception {

    }

    @Test
    public void testGetOAuthApplicationDataByAppName() throws Exception {

    }

    @DataProvider(name = "getRegisterOAuthApplicationData")
    public Object[][] getRegisterOAuthApplicationData() {
        return new Object[][] { { OAuthConstants.OAuthVersions.VERSION_2, "admin" },
                                { OAuthConstants.OAuthVersions.VERSION_2, null },
                                { null, "admin" }
        };
    }

    @Test(dataProvider = "getRegisterOAuthApplicationData")
    public void testRegisterOAuthApplicationData(String oauthVersion, String userName) throws Exception {

        IdentityCoreServiceComponent identityCoreServiceComponent = new IdentityCoreServiceComponent();
        ConfigurationContextService configurationContextService = new ConfigurationContextService
                (configurationContext, null);
        Whitebox.setInternalState(identityCoreServiceComponent, "configurationContextService",
                                  configurationContextService);
        when(configurationContext.getAxisConfiguration()).thenReturn(axisConfiguration);


        IdentityTenantUtil.setRealmService(realmService);
        when(realmService.getBootstrapRealmConfiguration()).thenReturn(realmConfiguration);

        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain("carbon.super");
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantId(-1234);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername(userName);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setUserRealm(userRealm);

        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userStoreManager.isExistingUser(userName)).thenReturn(true);

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

        oAuthAdminService.registerOAuthApplicationData(oAuthConsumerAppDTO);
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

    }

    @Test
    public void testRemoveOAuthApplicationData() throws Exception {

    }
}