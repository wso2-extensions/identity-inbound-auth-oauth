
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

import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDAO;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.dto.OAuthConsumerAppDTO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.nio.file.Paths;

import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

/**
 * Unit tests for OAuthAdminService.
 */
@PowerMockIgnore({"javax.net.*", "javax.security.*", "javax.crypto.*"})
@PrepareForTest({CarbonContext.class, IdentityUtil.class, MultitenantUtils.class, OAuthAppDAO.class,
OAuthAdminService.class, OAuthServerConfiguration.class})
public class OAuthAdminServiceTest extends PowerMockTestCase {

    @Mock
    private CarbonContext carbonContext;

    @Mock
    private OAuthAppDAO oAuthAppDAO;

    @BeforeClass
    public void setCarbonHome() {

        String carbonHome = Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString();
        System.setProperty(CarbonBaseConstants.CARBON_HOME, carbonHome);
    }

    @Test
    public void testGetAllOAuthApplicationData() throws Exception {

        String username = "Moana";
        String tenantAwareUserName = username;
        int tenantId = MultitenantConstants.SUPER_TENANT_ID;

        mockStatic(CarbonContext.class);
        when(CarbonContext.getThreadLocalCarbonContext()).thenReturn(carbonContext);
        when(carbonContext.getUsername()).thenReturn(username);
        when(carbonContext.getTenantId()).thenReturn(tenantId);
        mockStatic(MultitenantUtils.class);
        when(MultitenantUtils.getTenantAwareUsername(anyString())).thenReturn(tenantAwareUserName);
        OAuthAppDO app = getDummyOAuthApp(username);
        when(oAuthAppDAO.getOAuthConsumerAppsOfUser(tenantAwareUserName, tenantId)).thenReturn(new OAuthAppDO[]{app});
        whenNew(OAuthAppDAO.class).withAnyArguments().thenReturn(oAuthAppDAO);

        OAuthAdminService oAuthAdminService = new OAuthAdminService();
        OAuthConsumerAppDTO[] oAuthConsumerApps = oAuthAdminService.getAllOAuthApplicationData();
        assertTrue((oAuthConsumerApps.length == 1), "OAuth consumer application count should be one.");
        assertEquals(oAuthConsumerApps[0].getApplicationName(), app.getApplicationName(), "Application Name should be" +
                " as same as the given application name in the app data object.");
    }

    @Test(expectedExceptions = IdentityOAuthAdminException.class)
    public void testGetAllOAuthApplicationDataException() throws Exception {

        mockStatic(CarbonContext.class);
        when(CarbonContext.getThreadLocalCarbonContext()).thenReturn(carbonContext);
        when(carbonContext.getUsername()).thenReturn(null);
        mockStatic(CarbonContext.class);
        when(CarbonContext.getThreadLocalCarbonContext()).thenReturn(carbonContext);
        mockStatic(MultitenantUtils.class);
        whenNew(OAuthAppDAO.class).withAnyArguments().thenReturn(oAuthAppDAO);

        OAuthAdminService oAuthAdminService = new OAuthAdminService();
        oAuthAdminService.getAllOAuthApplicationData();
    }

    @Test
    public void testGetOAuthApplicationData() throws Exception {

        String consumerKey = "some-consumer-key";

        OAuthAppDO app = getDummyOAuthApp("some-user-name");
        when(oAuthAppDAO.getAppInformation(consumerKey)).thenReturn(app);
        whenNew(OAuthAppDAO.class).withAnyArguments().thenReturn(oAuthAppDAO);

        OAuthAdminService oAuthAdminService = new OAuthAdminService();
        OAuthConsumerAppDTO oAuthConsumerApp = oAuthAdminService.getOAuthApplicationData(consumerKey);
        assertEquals(oAuthConsumerApp.getApplicationName(), app.getApplicationName(), "Application name should be " +
                "same as the application name in app data object.");
    }

    @DataProvider(name = "getAppInformationExceptions")
    public Object[][] getAppInformationExceptions(){
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
        OAuthAppDO app = getDummyOAuthApp("some-user-name");
        when(oAuthAppDAO.getAppInformationByAppName(appName)).thenReturn(app);
        whenNew(OAuthAppDAO.class).withAnyArguments().thenReturn(oAuthAppDAO);

        OAuthAdminService oAuthAdminService = new OAuthAdminService();
        OAuthConsumerAppDTO oAuthConsumerApp = oAuthAdminService.getOAuthApplicationDataByAppName(appName);
        assertEquals(oAuthConsumerApp.getApplicationName(), app.getApplicationName(), "Application name should be " +
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
}
