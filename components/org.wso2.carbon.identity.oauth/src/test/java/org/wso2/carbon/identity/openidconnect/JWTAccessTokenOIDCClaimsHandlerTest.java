package org.wso2.carbon.identity.openidconnect;

/**
 * Class which tests JWTAccessTokenOIDCClaimsHandler.
 */

import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.commons.dbcp.BasicDataSource;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataHandler;
import org.wso2.carbon.identity.core.persistence.JDBCPersistenceManager;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.io.File;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.wso2.carbon.identity.core.util.IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR_DEFAULT;

@Listeners(MockitoTestNGListener.class)
public class JWTAccessTokenOIDCClaimsHandlerTest {

    public static final String DB_NAME = "jdbc/WSO2CarbonDB";
    public static final String H2_SCRIPT_NAME = "dbScripts/identity.sql";
    public static final String H2_SCRIPT2_NAME = "dbScripts/insert_scope_claim.sql";
    private static final String TENANT_DOMAIN = "foo.com";
    private static final String SERVICE_PROVIDER_NAME = "sampleSP";
    private static final String DUMMY_CLIENT_ID = "u5FIfG5xzLvBGiamoAYzzcqpBqga";
    private static final String USER_NAME = "peter";
    private static final String USER_STORE_DOMAIN = "H2";
    private static final String OIDC_DIALECT = "http://wso2.org/oidc/claim";
    private static final String CARBON_HOME =
            Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString();
    private static final Log log = LogFactory.getLog(JWTAccessTokenOIDCClaimsHandlerTest.class);
    Connection connection = null;
    @Mock
    private ApplicationManagementService applicationManagementService;
    @Mock
    ClaimMetadataHandler mockClaimMetadataHandler;
    private MockedStatic<FrameworkUtils> frameworkUtils;

    public static String getFilePath(String fileName) {

        if (StringUtils.isNotBlank(fileName)) {
            URL url = DefaultOIDCClaimsCallbackHandlerTest.class.getClassLoader().getResource(fileName);
            if (url != null) {
                try {
                    File file = new File(url.toURI());
                    return file.getAbsolutePath();
                } catch (URISyntaxException e) {
                    throw new IllegalArgumentException("Could not resolve a file with given path: " +
                            url.toExternalForm());
                }
            }
        }
        throw new IllegalArgumentException("DB Script file name cannot be empty.");
    }

    @BeforeMethod
    public void setUpBeforeMethod() throws Exception {
        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext privilegedCarbonContext = PrivilegedCarbonContext.getThreadLocalCarbonContext();
        privilegedCarbonContext.setTenantId(MultitenantConstants.SUPER_TENANT_ID);
        privilegedCarbonContext.setTenantDomain(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);

        frameworkUtils = mockStatic(FrameworkUtils.class);
        frameworkUtils.when(FrameworkUtils::getMultiAttributeSeparator).thenReturn(MULTI_ATTRIBUTE_SEPARATOR_DEFAULT);
    }

    @AfterMethod
    public void tearDown() throws Exception {

        PrivilegedCarbonContext.endTenantFlow();
        if (connection != null) {
            connection.close();
        }
        frameworkUtils.close();
    }

    @BeforeTest
    public void setUp() throws Exception {

        System.setProperty(CarbonBaseConstants.CARBON_HOME, CARBON_HOME);
        BasicDataSource dataSource1 = new BasicDataSource();
        dataSource1.setDriverClassName("org.h2.Driver");
        dataSource1.setUsername("username");
        dataSource1.setPassword("password");
        dataSource1.setUrl("jdbc:h2:mem:test" + DB_NAME);
        connection = dataSource1.getConnection();
        try {
            connection.createStatement().executeUpdate("RUNSCRIPT FROM '" + getFilePath(H2_SCRIPT_NAME) + "'");
            connection.createStatement().executeUpdate("RUNSCRIPT FROM '" + getFilePath(H2_SCRIPT2_NAME) + "'");
        } catch (SQLException e) {
            log.error("Error while running the script: " + H2_SCRIPT2_NAME);
        }
    }

    @Test
    public void testHandleCustomClaimsWithOAuthTokenReqMsgContextNoJWTATClaims() throws Exception {

        try (MockedStatic<JDBCPersistenceManager> jdbcPersistenceManager = mockStatic(JDBCPersistenceManager.class);
             MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                     OAuthServerConfiguration.class)) {
            OAuthServerConfiguration oauthServerConfigurationMock = mock(OAuthServerConfiguration.class);
            oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance)
                    .thenReturn(oauthServerConfigurationMock);
            try (MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class)) {

                OAuthAppDO oAuthAppDO = new OAuthAppDO();
                oAuthAppDO.setPkceMandatory(false);
                oAuthAppDO.setPkceSupportPlain(false);
                oAuth2Util.when(() -> OAuth2Util.getAppInformationByClientId(any(), any())).thenReturn(oAuthAppDO);

                OAuthTokenReqMessageContext requestMsgCtx = getTokenReqMessageContextForLocalUser();

                JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
                JWTClaimsSet jwtClaimsSet = getJwtClaimSet(jwtClaimsSetBuilder, requestMsgCtx, jdbcPersistenceManager,
                        oAuthServerConfiguration);
                assertNotNull(jwtClaimsSet);
                assertTrue(jwtClaimsSet.getClaims().isEmpty());
            }
        }
    }

    @Test
    public void testHandleCustomClaimsWithOAuthTokenReqMsgContextNoRegisteredOIDCClaims() throws Exception {

        try (MockedStatic<JDBCPersistenceManager> jdbcPersistenceManager = mockStatic(JDBCPersistenceManager.class);
             MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                     OAuthServerConfiguration.class)) {
            OAuthServerConfiguration oauthServerConfigurationMock = mock(OAuthServerConfiguration.class);
            oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance)
                    .thenReturn(oauthServerConfigurationMock);
            try (MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class);
                 MockedStatic<ClaimMetadataHandler> claimMetadataHandler = mockStatic(ClaimMetadataHandler.class)) {

                claimMetadataHandler.when(ClaimMetadataHandler::getInstance).thenReturn(this.mockClaimMetadataHandler);

                OAuthAppDO oAuthAppDO = new OAuthAppDO();
                oAuthAppDO.setPkceMandatory(false);
                oAuthAppDO.setPkceSupportPlain(false);
                String[] jwtAccessTokenClaims = new String[]{"given_name", "family_name", "email", "address", "roles",
                        "groups"};
                oAuthAppDO.setJwtAccessTokenClaims(jwtAccessTokenClaims);
                oAuth2Util.when(() -> OAuth2Util.getAppInformationByClientId(any(), any())).thenReturn(oAuthAppDO);

                OAuthTokenReqMessageContext requestMsgCtx = getTokenReqMessageContextForLocalUser();

                JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
                JWTClaimsSet jwtClaimsSet = getJwtClaimSet(jwtClaimsSetBuilder, requestMsgCtx, jdbcPersistenceManager,
                        oAuthServerConfiguration);
                assertNotNull(jwtClaimsSet);
                assertTrue(jwtClaimsSet.getClaims().isEmpty());
            }
        }
    }

    @Test
    public void testHandleCustomClaimsWithOAuthTokenReqMsgContextNoRegisteredOIDCClaims2() throws Exception {

        try (MockedStatic<JDBCPersistenceManager> jdbcPersistenceManager = mockStatic(JDBCPersistenceManager.class);
             MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                     OAuthServerConfiguration.class);
             MockedStatic<ClaimMetadataHandler> claimMetadataHandler = mockStatic(ClaimMetadataHandler.class)) {

            OAuthServerConfiguration oauthServerConfigurationMock = mock(OAuthServerConfiguration.class);
            oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance)
                    .thenReturn(oauthServerConfigurationMock);

            try (MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class)) {

                OAuthAppDO oAuthAppDO = new OAuthAppDO();
                oAuthAppDO.setPkceMandatory(false);
                oAuthAppDO.setPkceSupportPlain(false);
                String[] jwtAccessTokenClaims = new String[]{"given_name", "family_name", "email", "address", "roles",
                        "groups"};
                oAuthAppDO.setJwtAccessTokenClaims(jwtAccessTokenClaims);
                oAuth2Util.when(() -> OAuth2Util.getAppInformationByClientId(any(), any())).thenReturn(oAuthAppDO);

                Map<String, String> mappings = new HashMap<>();
                mappings.put("given_name", "http://wso2.org/given_name");
                mappings.put("family_name", "http://wso2.org/family_name");
                mappings.put("email", "http://wso2.org/email");
                mappings.put("address", "http://wso2.org/address");
                mappings.put("roles", "http://wso2.org/roles");
                mappings.put("groups", "http://wso2.org/groups");
                claimMetadataHandler.when(ClaimMetadataHandler::getInstance).thenReturn(mockClaimMetadataHandler);
                lenient().when(mockClaimMetadataHandler.getMappingsMapFromOtherDialectToCarbon(
                        anyString(), isNull(), anyString(), anyBoolean())).thenReturn(mappings);

                OAuthTokenReqMessageContext requestMsgCtx = getTokenReqMessageContextForLocalUser();

                JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
                JWTClaimsSet jwtClaimsSet = getJwtClaimSet(jwtClaimsSetBuilder, requestMsgCtx, jdbcPersistenceManager,
                        oAuthServerConfiguration);
                assertNotNull(jwtClaimsSet);
                assertTrue(jwtClaimsSet.getClaims().isEmpty());
            }
        }
    }

    private JWTClaimsSet getJwtClaimSet(JWTClaimsSet.Builder jwtClaimsSetBuilder,
                                        OAuthTokenReqMessageContext requestMsgCtx,
                                        MockedStatic<JDBCPersistenceManager> jdbcPersistenceManager,
                                        MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration)
            throws IdentityOAuth2Exception {

        OAuthServerConfiguration mockOAuthServerConfiguration = mock(OAuthServerConfiguration.class);
//        DataSource dataSource = mock(DataSource.class);
//        JDBCPersistenceManager mockJdbcPersistenceManager = mock(JDBCPersistenceManager.class);
        oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance).thenReturn(mockOAuthServerConfiguration);
//        when(mockOAuthServerConfiguration.isConvertOriginalClaimsFromAssertionsToOIDCDialect()).thenReturn(true);
        JWTClaimsSet jwtClaimsSet = null;

//        try {
//            if (connection.isClosed()) {
//
//                BasicDataSource dataSource1 = new BasicDataSource();
//                dataSource1.setDriverClassName("org.h2.Driver");
//                dataSource1.setUsername("username");
//                dataSource1.setPassword("password");
//                dataSource1.setUrl("jdbc:h2:mem:test" + DB_NAME);
//                Connection connection1 = null;
//                connection1 = dataSource1.getConnection();
//                lenient().when(dataSource.getConnection()).thenReturn(connection1);
//
//            } else {
//                lenient().when(dataSource.getConnection()).thenReturn(connection);
//            }
//        } catch (Exception e) {
//            log.error("Error while obtaining the datasource. ");
//        }
//
//        jdbcPersistenceManager.when(JDBCPersistenceManager::getInstance).thenReturn(mockJdbcPersistenceManager);
//        lenient().when(mockJdbcPersistenceManager.getDataSource()).thenReturn(dataSource);

        JWTAccessTokenOIDCClaimsHandler jWTAccessTokenOIDCClaimsHandler =
                new JWTAccessTokenOIDCClaimsHandler();
        jwtClaimsSet = jWTAccessTokenOIDCClaimsHandler.handleCustomClaims(jwtClaimsSetBuilder, requestMsgCtx);

        return jwtClaimsSet;
    }

    private OAuthTokenReqMessageContext getTokenReqMessageContextForLocalUser() {

        OAuth2AccessTokenReqDTO accessTokenReqDTO = new OAuth2AccessTokenReqDTO();
        accessTokenReqDTO.setTenantDomain(TENANT_DOMAIN);
        accessTokenReqDTO.setClientId(DUMMY_CLIENT_ID);

        OAuthTokenReqMessageContext requestMsgCtx = new OAuthTokenReqMessageContext(accessTokenReqDTO);
        requestMsgCtx.setAuthorizedUser(getDefaultAuthenticatedLocalUser());
        return requestMsgCtx;
    }

    private AuthenticatedUser getDefaultAuthenticatedLocalUser() {

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName(USER_NAME);
        authenticatedUser.setUserId(StringUtils.EMPTY);
        authenticatedUser.setUserStoreDomain(USER_STORE_DOMAIN);
        authenticatedUser.setTenantDomain(TENANT_DOMAIN);
        authenticatedUser.setFederatedUser(false);
        return authenticatedUser;
    }

    private void mockApplicationManagementService() throws Exception {

        when(applicationManagementService.getServiceProviderNameByClientId(anyString(), anyString(), anyString()))
                .thenReturn(SERVICE_PROVIDER_NAME);
        setStaticField(OAuth2ServiceComponentHolder.class, "applicationMgtService", applicationManagementService);
    }

    private void setStaticField(Class classname,
                                String fieldName,
                                Object value)
            throws NoSuchFieldException, IllegalAccessException, NoSuchMethodException, InvocationTargetException {

        Field declaredField = classname.getDeclaredField(fieldName);
        declaredField.setAccessible(true);

        Method getDeclaredFields0 = Class.class.getDeclaredMethod("getDeclaredFields0", boolean.class);
        getDeclaredFields0.setAccessible(true);
        Field[] fields = (Field[]) getDeclaredFields0.invoke(Field.class, false);
        Field modifiers = null;
        for (Field each : fields) {
            if ("modifiers".equals(each.getName())) {
                modifiers = each;
                break;
            }
        }
        modifiers.setAccessible(true);
        modifiers.setInt(declaredField, declaredField.getModifiers() & ~Modifier.FINAL);

        declaredField.set(null, value);
    }

}
