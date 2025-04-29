/*
 * Copyright (c) 2017-2024, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.oauth.endpoint.authz;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.SerializationUtils;
import org.apache.oltu.oauth2.as.request.OAuthAuthzRequest;
import org.apache.oltu.oauth2.as.validator.CodeValidator;
import org.apache.oltu.oauth2.as.validator.TokenValidator;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.message.types.ResponseType;
import org.apache.oltu.oauth2.common.validators.OAuthValidator;
import org.h2.jdbc.JdbcSQLIntegrityConstraintViolationException;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.mockito.stubbing.Answer;
import org.osgi.framework.BundleContext;
import org.osgi.util.tracker.ServiceTracker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.testng.collections.Sets;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.context.internal.OSGiDataHolder;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.CommonAuthenticationHandler;
import org.wso2.carbon.identity.application.authentication.framework.cache.AuthenticationResultCacheEntry;
import org.wso2.carbon.identity.application.authentication.framework.context.SessionContext;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.RequestCoordinator;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.impl.consent.ConsentClaimsData;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.impl.consent.SSOConsentService;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.impl.consent.exception.SSOConsentServiceException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationResult;
import org.wso2.carbon.identity.application.authentication.framework.model.CommonAuthRequestWrapper;
import org.wso2.carbon.identity.application.authentication.framework.model.CommonAuthResponseWrapper;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.model.ServiceProviderProperty;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.central.log.mgt.internal.CentralLogMgtServiceComponentHolder;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataHandler;
import org.wso2.carbon.identity.claim.metadata.mgt.model.ExternalClaim;
import org.wso2.carbon.identity.common.testng.TestConstants;
import org.wso2.carbon.identity.core.ServiceURL;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.oauth.OAuthAdminServiceImpl;
import org.wso2.carbon.identity.oauth.cache.SessionDataCache;
import org.wso2.carbon.identity.oauth.cache.SessionDataCacheEntry;
import org.wso2.carbon.identity.oauth.cache.SessionDataCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.dto.OAuthErrorDTO;
import org.wso2.carbon.identity.oauth.endpoint.exception.InvalidRequestException;
import org.wso2.carbon.identity.oauth.endpoint.exception.InvalidRequestParentException;
import org.wso2.carbon.identity.oauth.endpoint.expmapper.InvalidRequestExceptionMapper;
import org.wso2.carbon.identity.oauth.endpoint.message.OAuthMessage;
import org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil;
import org.wso2.carbon.identity.oauth.endpoint.util.OpenIDConnectUserRPStore;
import org.wso2.carbon.identity.oauth.endpoint.util.TestOAuthEndpointBase;
import org.wso2.carbon.identity.oauth.endpoint.util.factory.OAuth2ServiceFactory;
import org.wso2.carbon.identity.oauth.endpoint.util.factory.OAuth2TokenValidatorServiceFactory;
import org.wso2.carbon.identity.oauth.endpoint.util.factory.OAuthAdminServiceFactory;
import org.wso2.carbon.identity.oauth.endpoint.util.factory.OAuthServerConfigurationFactory;
import org.wso2.carbon.identity.oauth.endpoint.util.factory.Oauth2ScopeServiceFactory;
import org.wso2.carbon.identity.oauth.endpoint.util.factory.SSOConsentServiceFactory;
import org.wso2.carbon.identity.oauth.rar.model.AuthorizationDetail;
import org.wso2.carbon.identity.oauth.rar.model.AuthorizationDetails;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.OAuth2ScopeService;
import org.wso2.carbon.identity.oauth2.OAuth2Service;
import org.wso2.carbon.identity.oauth2.OAuth2TokenValidationService;
import org.wso2.carbon.identity.oauth2.RequestObjectException;
import org.wso2.carbon.identity.oauth2.authz.AuthorizationHandlerManager;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2ClientValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.oauth2.rar.AuthorizationDetailsService;
import org.wso2.carbon.identity.oauth2.rar.validator.AuthorizationDetailsValidator;
import org.wso2.carbon.identity.oauth2.responsemode.provider.ResponseModeProvider;
import org.wso2.carbon.identity.oauth2.responsemode.provider.impl.DefaultResponseModeProvider;
import org.wso2.carbon.identity.oauth2.responsemode.provider.impl.FormPostResponseModeProvider;
import org.wso2.carbon.identity.oauth2.responsemode.provider.impl.FragmentResponseModeProvider;
import org.wso2.carbon.identity.oauth2.responsemode.provider.impl.QueryResponseModeProvider;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oidc.session.OIDCSessionManager;
import org.wso2.carbon.identity.oidc.session.OIDCSessionState;
import org.wso2.carbon.identity.oidc.session.util.OIDCSessionManagementUtil;
import org.wso2.carbon.identity.openidconnect.OIDCConstants;
import org.wso2.carbon.identity.openidconnect.OpenIDConnectClaimFilterImpl;
import org.wso2.carbon.identity.openidconnect.RequestObjectBuilder;
import org.wso2.carbon.identity.openidconnect.RequestObjectService;
import org.wso2.carbon.identity.openidconnect.RequestObjectValidatorImpl;
import org.wso2.carbon.identity.openidconnect.RequestParamRequestObjectBuilder;
import org.wso2.carbon.identity.openidconnect.model.RequestObject;
import org.wso2.carbon.identity.openidconnect.model.RequestedClaim;
import org.wso2.carbon.utils.CarbonUtils;

import java.io.FileInputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.security.interfaces.RSAPrivateKey;
import java.sql.Connection;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Vector;
import java.util.concurrent.ConcurrentHashMap;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.ws.rs.HttpMethod;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anySet;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doCallRealMethod;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.testng.FileAssert.fail;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.SUBJECT_TOKEN;
import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.EXP;
import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.NBF;
import static org.wso2.carbon.identity.openidconnect.OIDCRequestObjectUtil.REQUEST_PARAM_VALUE_BUILDER;

public class OAuth2AuthzEndpointTest extends TestOAuthEndpointBase {

    private static final Logger log = LoggerFactory.getLogger(OAuth2AuthzEndpointTest.class);
    @Mock
    HttpServletRequest httpServletRequest;

    @Mock
    HttpServletResponse httpServletResponse;

    @Mock
    SessionDataCache mockSessionDataCache;

    @Mock
    SessionDataCacheEntry loginCacheEntry, consentCacheEntry;

    @Mock
    OAuthServerConfiguration mockOAuthServerConfiguration;

    @Mock
    TokenPersistenceProcessor tokenPersistenceProcessor;

    @Mock
    OAuth2Service oAuth2Service;

    @Mock
    OAuthAdminServiceImpl oAuthAdminService;

    @Mock
    OAuth2ScopeService oAuth2ScopeService;

    @Mock
    RequestObjectService requestObjectService;

    @Mock
    HttpSession httpSession;

    @Mock
    RequestCoordinator requestCoordinator;

    @Mock
    OpenIDConnectUserRPStore mockOpenIDConnectUserRPStore;

    @Mock
    OAuth2ClientValidationResponseDTO oAuth2ClientValidationResponseDTO;

    @Mock
    OAuthAuthzRequest oAuthAuthzRequest;

    @Mock
    SignedJWT mockSignedJWT;

    @Mock
    OIDCSessionManager oidcSessionManager;

    @Mock
    OAuthMessage oAuthMessage;

    @Mock
    OAuthErrorDTO oAuthErrorDTO;

    @Mock
    OAuthProblemException oAuthProblemException;

    @Mock
    Cookie authCookie;

    @Mock
    OpenIDConnectClaimFilterImpl openIDConnectClaimFilter;

    @Mock
    ClaimMetadataHandler mockClaimMetadataHandler;

    @Mock
    ServletContext servletContext;

    @Mock
    RequestDispatcher requestDispatcher;

    @Mock
    AuthorizationHandlerManager mockAuthorizationHandlerManager;

    @Mock
    private CentralLogMgtServiceComponentHolder centralLogMgtServiceComponentHolderMock;

    @Mock
    SSOConsentService mockedSSOConsentService;

    @Mock
    OAuth2TokenValidationService oAuth2TokenValidator;

    @Mock
    BundleContext bundleContext;

    MockedConstruction<ServiceTracker> mockedConstruction;

    @Mock
    private AuthorizationDetailsService authorizationDetailsServiceMock;

    @Mock
    private AuthorizationDetailsValidator authorizationDetailsValidatorMock;

    private static final String ERROR_PAGE_URL = "https://localhost:9443/authenticationendpoint/oauth2_error.do";
    private static final String LOGIN_PAGE_URL = "https://localhost:9443/authenticationendpoint/login.do";
    private static final String USER_CONSENT_URL =
            "https://localhost:9443/authenticationendpoint/oauth2_authz.do";
    private static final String CLIENT_ID = "client_id";
    private static final String REDIRECT_URI = "redirect_uri";
    private static final String RESPONSE_MODE = "response_mode";
    private static final String RESPONSE_MODE_FORM_POST = "form_post";
    private static final String SESSION_DATA_KEY_CONSENT_VALUE = "savedSessionDataKeyForConsent";
    private static final String SESSION_DATA_KEY_VALUE = "savedSessionDataKey";
    private static final String CLIENT_ID_VALUE = "ca19a540f544777860e44e75f605d927";
    private static final String APP_NAME = "myApp";
    private static final String INACTIVE_CLIENT_ID_VALUE = "inactiveId";
    private static final String SECRET = "87n9a540f544777860e44e75f605d435";
    private static final String INACTIVE_APP_NAME = "inactiveApp";
    private static final String USERNAME = "user1";
    public static final String USER_ID = "4b4414e1-916b-4475-aaee-6b0751c29ff6";
    private static final String APP_REDIRECT_URL = "http://localhost:8080/redirect";
    private static final String APP_REDIRECT_URL_JSON = "{\"url\":\"http://localhost:8080/redirect\"}";
    private static final String SP_DISPLAY_NAME = "DisplayName";
    private static final String SP_NAME = "Name";
    private static final String STATE = "JEZGpTb8IF";
    private static final String OIDC_DIALECT = "http://wso2.org/oidc/claim";
    private static final int MILLISECONDS_PER_SECOND = 1000;
    private static final int TIME_MARGIN_IN_SECONDS = 3000;
    private static final String INVALID_CLIENT_ID = "invalidId";

    private OAuth2AuthzEndpoint oAuth2AuthzEndpoint;
    private Object authzEndpointObject;
    private ServiceProvider dummySp;

    private KeyStore clientKeyStore;
    private MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil;
    private AutoCloseable closeable;

    @BeforeClass
    public void setUp() throws Exception {

        System.setProperty(
                CarbonBaseConstants.CARBON_HOME,
                Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString()
                          );
        oAuth2AuthzEndpoint = new OAuth2AuthzEndpoint();

        initiateInMemoryH2();
        try {
            createOAuthApp(CLIENT_ID_VALUE, SECRET, USERNAME, APP_NAME, "ACTIVE");
        } catch (JdbcSQLIntegrityConstraintViolationException e) {
            // ignore
        }
        try {
            createOAuthApp(INACTIVE_CLIENT_ID_VALUE, "dummySecret", USERNAME, INACTIVE_APP_NAME,
                    "INACTIVE");
        } catch (JdbcSQLIntegrityConstraintViolationException e) {
            // ignore
        }

        Class<?> clazz = OAuth2AuthzEndpoint.class;
        authzEndpointObject = clazz.newInstance();

        dummySp = new ServiceProvider();
        dummySp.setApplicationResourceId("sampleApp");
    }

    @BeforeMethod
    public void setUpMethod() {

        closeable = MockitoAnnotations.openMocks(this);
        identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class);
        mockDatabase(identityDatabaseUtil);
        IdentityEventService identityEventService = mock(IdentityEventService.class);
        CentralLogMgtServiceComponentHolder.getInstance().setIdentityEventService(identityEventService);

        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain("carbon.super");

        ArgumentCaptor<String> argumentCaptor = ArgumentCaptor.forClass(String.class);
        mockedConstruction = mockConstruction(ServiceTracker.class,
                (mock, context) -> {
                    verify(bundleContext, atLeastOnce()).createFilter(argumentCaptor.capture());
                    if (argumentCaptor.getValue().contains(OAuth2Service.class.getName())) {
                        when(mock.getServices()).thenReturn(new Object[]{oAuth2Service});
                    }
                    if (argumentCaptor.getValue().contains(OpenIDConnectClaimFilterImpl.class.getName())) {
                        when(mock.getServices()).thenReturn(new Object[]{openIDConnectClaimFilter});
                    }
                    if (argumentCaptor.getValue().contains(SSOConsentService.class.getName())) {
                        when(mock.getServices()).thenReturn(new Object[]{mockedSSOConsentService});
                    }
                    if (argumentCaptor.getValue().contains(RequestObjectService.class.getName())) {
                        when(mock.getServices()).thenReturn(new Object[]{requestObjectService});
                    }
                    if (argumentCaptor.getValue().contains(OAuthAdminServiceImpl.class.getName())) {
                        when(mock.getServices()).thenReturn(new Object[]{oAuthAdminService});
                    }
                    if (argumentCaptor.getValue().contains(OAuth2ScopeService.class.getName())) {
                        when(mock.getServices()).thenReturn(new Object[]{oAuth2ScopeService});
                    }
                    if (argumentCaptor.getValue().contains(OAuthServerConfiguration.class.getName())) {
                        when(mock.getServices()).thenReturn(new Object[]{mockOAuthServerConfiguration});
                    }
                    if (argumentCaptor.getValue().contains(OAuth2TokenValidationService.class.getName())) {
                        when(mock.getServices()).thenReturn(new Object[]{oAuth2TokenValidator});
                    }
                });
        OSGiDataHolder.getInstance().setBundleContext(bundleContext);
    }

    @AfterMethod
    public void tearDownMethod() throws Exception {

        if (identityDatabaseUtil != null) {
            identityDatabaseUtil.close();
        }
        Mockito.reset(oAuth2ScopeService);
        mockedConstruction.close();
        PrivilegedCarbonContext.endTenantFlow();
        closeable.close();
    }

    @AfterClass
    public void tearDown() throws Exception {

        super.cleanData();
        CentralLogMgtServiceComponentHolder.getInstance().setIdentityEventService(null);
    }

    @DataProvider(name = "providePostParams")
    public Object[][] providePostParams() {

        MultivaluedMap<String, String> paramMap1 = new MultivaluedHashMap<>();
        List<String> list1 = new ArrayList<>();
        list1.add("value1");
        list1.add("value2");
        paramMap1.put("paramName1", list1);

        Map<String, String[]> requestParams1 = new HashMap<>();
        requestParams1.put("reqParam1", new String[]{"val1", "val2"});

        MultivaluedMap<String, String> paramMap2 = new MultivaluedHashMap<>();
        List<String> list2 = new ArrayList<>();
        list2.add("value1");
        paramMap2.put("paramName1", list2);

        Map<String, String[]> requestParams2 = new HashMap<>();
        requestParams2.put("reqParam1", new String[]{"val1"});

        return addDiagnosticLogStatusToExistingDataProvider(new Object[][]{
                {paramMap2, requestParams2, HttpServletResponse.SC_FOUND},
                {paramMap1, requestParams2, HttpServletResponse.SC_BAD_REQUEST},
        });
    }

    @Test(dataProvider = "providePostParams")
    public void testAuthorizePost(Object paramObject, Map<String, String[]> requestParams, int expected,
                                  boolean diagnosticLogsEnabled)
            throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);) {
            mockSSOConsentService(false);
            mockOAuthServerConfiguration(oAuthServerConfiguration);
            try (MockedStatic<LoggerUtils> loggerUtils = mockStatic(LoggerUtils.class);
                 MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
                 MockedStatic<OAuth2Util.OAuthURL> oAuthURL = mockStatic(OAuth2Util.OAuthURL.class)) {

                loggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(diagnosticLogsEnabled);
                MultivaluedMap<String, String> paramMap = (MultivaluedMap<String, String>) paramObject;
                when(httpServletRequest.getParameterMap()).thenReturn(requestParams);
                when(httpServletRequest.getParameterNames()).thenReturn(new Vector(requestParams.keySet()).elements());
                identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString()))
                        .thenReturn(MultitenantConstants.SUPER_TENANT_ID);
                oAuthURL.when(OAuth2Util.OAuthURL::getOAuth2ErrorPageUrl).thenReturn(ERROR_PAGE_URL);

                Response response;

                try {
                    response = oAuth2AuthzEndpoint.authorizePost(httpServletRequest, httpServletResponse, paramMap);
                } catch (InvalidRequestParentException ire) {
                    InvalidRequestExceptionMapper invalidRequestExceptionMapper = new InvalidRequestExceptionMapper();
                    response = invalidRequestExceptionMapper.toResponse(ire);
                }

                assertEquals(response.getStatus(), expected, "Unexpected HTTP response status");
            }
        }
    }

    @DataProvider(name = "provideParams")
    public Object[][] provideParams() {

        return addDiagnosticLogStatusToExistingDataProvider(new Object[][]{
                {AuthenticatorFlowStatus.SUCCESS_COMPLETED, new String[]{"val1", "val2"},
                        SESSION_DATA_KEY_CONSENT_VALUE, "true", "scope1", SESSION_DATA_KEY_VALUE, null,
                        HttpServletResponse.SC_BAD_REQUEST, OAuth2ErrorCodes.INVALID_REQUEST, null, false},

                {AuthenticatorFlowStatus.SUCCESS_COMPLETED, new String[]{CLIENT_ID_VALUE},
                        SESSION_DATA_KEY_CONSENT_VALUE, "true", "scope1", SESSION_DATA_KEY_VALUE, null,
                        HttpServletResponse.SC_FOUND, OAuth2ErrorCodes.INVALID_REQUEST, null, false},

                {null, new String[]{""}, null, "true", "scope1", null, null, HttpServletResponse.SC_FOUND, null, null,
                        false},

                {null, new String[]{""}, null, "false", "scope1", null, null, HttpServletResponse.SC_FOUND,
                        OAuth2ErrorCodes.INVALID_REQUEST, null, false},

                {null, new String[]{"invalidId"}, null, "false", "scope1", null, null, HttpServletResponse.SC_FOUND,
                        OAuth2ErrorCodes.INVALID_CLIENT, null, false},

                {null, new String[]{INACTIVE_CLIENT_ID_VALUE}, null, "false", "scope1", null, null,
                        HttpServletResponse.SC_FOUND, OAuth2ErrorCodes.INVALID_CLIENT, null, false},

                {AuthenticatorFlowStatus.SUCCESS_COMPLETED, new String[]{CLIENT_ID_VALUE}, "invalidConsentCacheKey",
                        "true", "scope1", SESSION_DATA_KEY_VALUE, null, HttpServletResponse.SC_FOUND,
                        OAuth2ErrorCodes.INVALID_REQUEST, null, false},

                {null, new String[]{CLIENT_ID_VALUE}, SESSION_DATA_KEY_CONSENT_VALUE, "false", "scope1",
                        SESSION_DATA_KEY_VALUE, null, HttpServletResponse.SC_FOUND, OAuth2ErrorCodes.INVALID_REQUEST,
                        null, false},

                {null, new String[]{CLIENT_ID_VALUE}, null, "true", "scope1",
                        null, new IOException(), HttpServletResponse.SC_INTERNAL_SERVER_ERROR, null, null, false},

                {AuthenticatorFlowStatus.SUCCESS_COMPLETED, new String[]{CLIENT_ID_VALUE}, null, "true", "scope1",
                        null, null, HttpServletResponse.SC_FOUND, OAuth2ErrorCodes.INVALID_REQUEST, null, false},

                {AuthenticatorFlowStatus.SUCCESS_COMPLETED, new String[]{CLIENT_ID_VALUE}, null, "true", "scope1",
                        null, OAuthProblemException.error("error"), HttpServletResponse.SC_FOUND,
                        OAuth2ErrorCodes.INVALID_REQUEST, null, false},

                {AuthenticatorFlowStatus.SUCCESS_COMPLETED, new String[]{CLIENT_ID_VALUE}, null, "true", "scope1",
                        null, new IOException(), HttpServletResponse.SC_FOUND, OAuth2ErrorCodes.INVALID_REQUEST, null,
                        false},

                {null, new String[]{CLIENT_ID_VALUE}, null, "false", null, null, null, HttpServletResponse.SC_FOUND,
                        OAuth2ErrorCodes.INVALID_REQUEST, null, false},

                {AuthenticatorFlowStatus.INCOMPLETE, new String[]{CLIENT_ID_VALUE}, null, "false",
                        OAuthConstants.Scope.OPENID, null, null, HttpServletResponse.SC_FOUND,
                        OAuth2ErrorCodes.INVALID_REQUEST, null, false},

                {AuthenticatorFlowStatus.INCOMPLETE, null, null, "false", OAuthConstants.Scope.OPENID, null, null,
                        HttpServletResponse.SC_FOUND, OAuth2ErrorCodes.INVALID_REQUEST, null, false},

                {AuthenticatorFlowStatus.SUCCESS_COMPLETED, new String[]{CLIENT_ID_VALUE}, null, "true", "scope1",
                        null, null, HttpServletResponse.SC_FOUND, OAuth2ErrorCodes.INVALID_REQUEST,
                        RESPONSE_MODE_FORM_POST, true},

                {AuthenticatorFlowStatus.SUCCESS_COMPLETED, new String[]{CLIENT_ID_VALUE}, null, "true", "scope1",
                        null, null, HttpServletResponse.SC_FOUND, OAuth2ErrorCodes.INVALID_REQUEST,
                        RESPONSE_MODE_FORM_POST, false}
        });
    }

    @Test(dataProvider = "provideParams", groups = "testWithConnection")
    public void testAuthorize(Object flowStatusObject, String[] clientId, String sessionDataKayConsent,
                              String toCommonAuth, String scope, String sessionDataKey, Exception e, int expectedStatus,
                              String expectedError, String responseMode, boolean isOAuthResponseJspPageAvailable,
                              boolean diagnosticLogsEnabled)
            throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);) {
            mockOAuthServerConfiguration(oAuthServerConfiguration);
            try (MockedStatic<OAuth2Util.OAuthURL> oAuthURL = mockStatic(OAuth2Util.OAuthURL.class);
                 MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
                 MockedStatic<LoggerUtils> loggerUtils = mockStatic(LoggerUtils.class);
                 MockedStatic<CentralLogMgtServiceComponentHolder> centralLogMgtServiceComponentHolder =
                         mockStatic(CentralLogMgtServiceComponentHolder.class);
                 MockedStatic<SessionDataCache> sessionDataCache = mockStatic(SessionDataCache.class);
                 MockedStatic<FrameworkUtils> frameworkUtils = mockStatic(FrameworkUtils.class,
                         Mockito.CALLS_REAL_METHODS);
                 MockedStatic<ServiceURLBuilder> serviceURLBuilder = mockStatic(ServiceURLBuilder.class);
                 MockedStatic<EndpointUtil> endpointUtil = mockStatic(EndpointUtil.class,
                         Mockito.CALLS_REAL_METHODS);
                 MockedStatic<OAuth2ServiceFactory> oAuth2ServiceFactory = mockStatic(OAuth2ServiceFactory.class);
                 MockedStatic<OAuthAdminServiceFactory> oAuthAdminServiceFactory =
                         mockStatic(OAuthAdminServiceFactory.class);
                 MockedStatic<OAuth2TokenValidatorServiceFactory> oAuth2TokenValidatorServiceFactory =
                         mockStatic(OAuth2TokenValidatorServiceFactory.class);) {
                AuthenticatorFlowStatus flowStatus = (AuthenticatorFlowStatus) flowStatusObject;

                Map<String, String[]> requestParams = new HashMap<>();
                Map<String, Object> requestAttributes = new HashMap<>();

                if (clientId != null) {
                    requestParams.put(CLIENT_ID, clientId);
                }
                requestParams.put(OAuthConstants.SESSION_DATA_KEY_CONSENT, new String[]{sessionDataKayConsent});
                requestParams.put(FrameworkConstants.RequestParams.TO_COMMONAUTH, new String[]{toCommonAuth});
                requestParams.put(OAuthConstants.OAuth20Params.SCOPE, new String[]{scope});
                if (StringUtils.equals(responseMode, RESPONSE_MODE_FORM_POST)) {
                    requestParams.put(RESPONSE_MODE, new String[]{RESPONSE_MODE_FORM_POST});
                    when(mockOAuthServerConfiguration.isOAuthResponseJspPageAvailable())
                            .thenReturn(isOAuthResponseJspPageAvailable);
                }

                requestAttributes.put(FrameworkConstants.RequestParams.FLOW_STATUS, flowStatus);
                requestAttributes.put(FrameworkConstants.SESSION_DATA_KEY, sessionDataKey);
                requestParams.put(REDIRECT_URI, new String[]{APP_REDIRECT_URL});

                if (e instanceof OAuthProblemException) {
                    requestParams.put(REDIRECT_URI, new String[]{APP_REDIRECT_URL});
                }

                mockHttpRequest(requestParams, requestAttributes, HttpMethod.POST);

                oAuthURL.when(OAuth2Util.OAuthURL::getOAuth2ErrorPageUrl).thenReturn(ERROR_PAGE_URL);

                frameworkUtils.when(() -> FrameworkUtils.startTenantFlow(anyString())).thenAnswer(invocation -> null);
                frameworkUtils.when(FrameworkUtils::endTenantFlow).thenAnswer(invocation -> null);

                loggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(diagnosticLogsEnabled);
                identityTenantUtil.when(() -> IdentityTenantUtil.getTenantDomain(anyInt()))
                        .thenReturn(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
                identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString()))
                        .thenReturn(MultitenantConstants.SUPER_TENANT_ID);
                identityTenantUtil.when(IdentityTenantUtil::getLoginTenantId)
                        .thenReturn(MultitenantConstants.SUPER_TENANT_ID);
                IdentityEventService eventServiceMock = mock(IdentityEventService.class);
                centralLogMgtServiceComponentHolder.when(
                                CentralLogMgtServiceComponentHolder::getInstance)
                        .thenReturn(centralLogMgtServiceComponentHolderMock);
                when(centralLogMgtServiceComponentHolderMock.getIdentityEventService()).thenReturn(eventServiceMock);
                doNothing().when(eventServiceMock).handleEvent(any());

                when(httpServletRequest.getServletContext()).thenReturn(servletContext);
                when(servletContext.getContext(anyString())).thenReturn(servletContext);
                when(servletContext.getRequestDispatcher(anyString())).thenReturn(requestDispatcher);
                doNothing().when(requestDispatcher).forward(any(ServletRequest.class), any(ServletResponse.class));

                sessionDataCache.when(SessionDataCache::getInstance).thenReturn(mockSessionDataCache);
                SessionDataCacheKey loginDataCacheKey = new SessionDataCacheKey(SESSION_DATA_KEY_VALUE);
                SessionDataCacheKey consentDataCacheKey = new SessionDataCacheKey(SESSION_DATA_KEY_CONSENT_VALUE);
                when(mockSessionDataCache.getValueFromCache(loginDataCacheKey)).thenReturn(loginCacheEntry);
                when(mockSessionDataCache.getValueFromCache(consentDataCacheKey)).thenReturn(consentCacheEntry);
                when(loginCacheEntry.getoAuth2Parameters()).thenReturn(setOAuth2Parameters(new HashSet<>(Collections
                        .singletonList(OAuthConstants.Scope.OPENID)), APP_NAME, null, null, null));

                mockEndpointUtil(false, endpointUtil);

                oAuth2ServiceFactory.when(OAuth2ServiceFactory::getOAuth2Service).thenReturn(oAuth2Service);
                oAuthAdminServiceFactory.when(OAuthAdminServiceFactory::getOAuthAdminService)
                        .thenReturn(oAuthAdminService);
                oAuth2TokenValidatorServiceFactory.when(OAuth2TokenValidatorServiceFactory
                                ::getOAuth2TokenValidatorService)
                        .thenReturn(oAuth2TokenValidator);
                when(oAuth2Service.getOauthApplicationState(CLIENT_ID_VALUE)).thenReturn("ACTIVE");
                doCallRealMethod().when(oAuth2Service).validateInputParameters(httpServletRequest);
                if (ArrayUtils.isNotEmpty(clientId) && (clientId[0].equalsIgnoreCase("invalidId") || clientId[0]
                        .equalsIgnoreCase(INACTIVE_CLIENT_ID_VALUE) || StringUtils.isEmpty(clientId[0]))) {
                    when(oAuth2Service.validateClientInfo(httpServletRequest)).thenCallRealMethod();

                } else {
                    when(oAuth2Service.validateClientInfo(httpServletRequest))
                            .thenReturn(oAuth2ClientValidationResponseDTO);
                    when(oAuth2ClientValidationResponseDTO.isValidClient()).thenReturn(true);
                }

                ApplicationManagementService appMgtService = mock(ApplicationManagementService.class);
                OAuth2ServiceComponentHolder.setApplicationMgtService(appMgtService);
                when(appMgtService.getServiceProviderByClientId(anyString(), any(), anyString())).thenReturn(dummySp);
                when(appMgtService.getServiceProviderByClientId(eq(INVALID_CLIENT_ID), any(), anyString()))
                        .thenReturn(null);

                try (MockedConstruction<CommonAuthenticationHandler> mockedConstruction = Mockito.mockConstruction(
                        CommonAuthenticationHandler.class,
                        (mock, context) -> {
                            if (e instanceof IOException) {
                                doThrow(e).when(mock).doGet(any(), any());
                            } else {
                                doAnswer(invocation -> {
                                    HttpServletRequest request = (HttpServletRequest) invocation.getArguments()[0];
                                    when(request.getAttribute(FrameworkConstants.RequestParams.FLOW_STATUS)).thenReturn(
                                            AuthenticatorFlowStatus.INCOMPLETE);
                                    CommonAuthResponseWrapper response =
                                            (CommonAuthResponseWrapper) invocation.getArguments()[1];
                                    response.sendRedirect(LOGIN_PAGE_URL);

                                    return null;
                                }).when(mock).doGet(any(), any());
                            }
                        })) {

                    Response response;
                    mockServiceURLBuilder(serviceURLBuilder);
                    try {
                        setSupportedResponseModes();
                        response = oAuth2AuthzEndpoint.authorize(httpServletRequest, httpServletResponse);
                    } catch (InvalidRequestParentException ire) {
                        InvalidRequestExceptionMapper invalidRequestExceptionMapper =
                                new InvalidRequestExceptionMapper();
                        response = invalidRequestExceptionMapper.toResponse(ire);
                    }

                    if (!StringUtils.equals(responseMode, RESPONSE_MODE_FORM_POST)) {
                        assertEquals(response.getStatus(), expectedStatus, "Unexpected HTTP response status");
                        MultivaluedMap<String, Object> responseMetadata = response.getMetadata();

                        assertNotNull(responseMetadata, "HTTP response metadata is null");

                        if (expectedStatus == HttpServletResponse.SC_FOUND) {
                            if (expectedError != null) {
                                List<Object> redirectPath = responseMetadata.get(HTTPConstants.HEADER_LOCATION);
                                if (CollectionUtils.isNotEmpty(redirectPath)) {
                                    String location = String.valueOf(redirectPath.get(0));
                                    assertTrue(location.contains(expectedError),
                                            "Expected error code not found in URL");
                                } else {
                                    assertNotNull(response.getEntity(), "Response entity is null");
                                    assertTrue(response.getEntity().toString().contains(expectedError),
                                            "Expected error code not found response entity");
                                }
                            } else {
                                // This is the case where a redirect outside happens.
                                List<Object> redirectPath = responseMetadata.get(HTTPConstants.HEADER_LOCATION);
                                assertTrue(CollectionUtils.isNotEmpty(redirectPath));
                                String location = String.valueOf(redirectPath.get(0));
                                assertNotNull(location);
                                assertFalse(location.contains("error"),
                                        "Expected no errors in the redirect url, but found one.");
                            }
                        }
                    } else {
                        if (expectedError != null) {
                            if (isOAuthResponseJspPageAvailable) {
                                assertEquals(response.getStatus(), 200);
                            } else {
                                // Check if the error response is of form post mode
                                assertTrue(response.getEntity().toString()
                                        .contains("<form method=\"post\" action=\"" + APP_REDIRECT_URL + "\">"));
                            }
                        }
                    }
                }
            }
        }
    }

    @DataProvider(name = "provideAuthenticatedData")
    public Object[][] provideAuthenticatedData() {

        final AuthorizationDetail testAuthorizationDetail = new AuthorizationDetail();
        testAuthorizationDetail.setType("test_type");

        return addDiagnosticLogStatusToExistingDataProvider(new Object[][]{
                {true, true, new HashMap(), null, null, null, new HashSet<>(Arrays.asList(OAuthConstants.Scope.OPENID)),
                        null, RESPONSE_MODE_FORM_POST, APP_REDIRECT_URL, HttpServletResponse.SC_FOUND},

                {false, true, null, null, null, null, new HashSet<>(Arrays.asList(OAuthConstants.Scope.OPENID)),
                        null, RESPONSE_MODE_FORM_POST, APP_REDIRECT_URL, HttpServletResponse.SC_FOUND},

                {true, true, new HashMap(), null, null, null, new HashSet<>(Arrays.asList("scope1")), null,
                        "not_form_post", APP_REDIRECT_URL, HttpServletResponse.SC_FOUND},

                {true, true, new HashMap(), null, null, null, new HashSet<>(Arrays.asList(OAuthConstants.Scope.OPENID)),
                        null, RESPONSE_MODE_FORM_POST, APP_REDIRECT_URL_JSON, HttpServletResponse.SC_OK},

                {true, true, new HashMap(), null, null, null, new HashSet<>(Arrays.asList("scope1")), null,
                        RESPONSE_MODE_FORM_POST, APP_REDIRECT_URL_JSON, HttpServletResponse.SC_OK},

                {true, false, null, OAuth2ErrorCodes.INVALID_REQUEST, null, null,
                        new HashSet<>(Arrays.asList("scope1")), null,
                        RESPONSE_MODE_FORM_POST, APP_REDIRECT_URL, HttpServletResponse.SC_OK},

                {true, false, null, null, "Error!", null, new HashSet<>(Arrays.asList(OAuthConstants.Scope.OPENID)),
                        null, RESPONSE_MODE_FORM_POST, APP_REDIRECT_URL, HttpServletResponse.SC_OK},

                {true, false, null, null, null, "http://localhost:8080/error",
                        new HashSet<>(Arrays.asList(OAuthConstants.Scope.OPENID)), null, RESPONSE_MODE_FORM_POST,
                        APP_REDIRECT_URL, HttpServletResponse.SC_OK},

                {true, true, new HashMap<>(), null, null, null, Sets.newHashSet("scope1"),
                        Sets.newHashSet(testAuthorizationDetail), RESPONSE_MODE_FORM_POST, APP_REDIRECT_URL_JSON,
                        HttpServletResponse.SC_OK}
        });
    }

    @Test(dataProvider = "provideAuthenticatedData", groups = "testWithConnection")
    public void testAuthorizeForAuthenticationResponse(boolean isResultInRequest, boolean isAuthenticated,
                                                       Map<ClaimMapping, String> attributes, String errorCode,
                                                       String errorMsg, String errorUri, Set<String> scopes,
                                                       Set<AuthorizationDetail> testAuthorizationDetails,
                                                       String responseMode, String redirectUri, int expected,
                                                       boolean diagnosticLogsEnabled)
            throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class)) {
            mockSSOConsentService(false);
            mockOAuthServerConfiguration(oAuthServerConfiguration);
            try (MockedStatic<SessionDataCache> sessionDataCache = mockStatic(SessionDataCache.class);
                 MockedStatic<LoggerUtils> loggerUtils = mockStatic(LoggerUtils.class);
                 MockedStatic<FrameworkUtils> frameworkUtils = mockStatic(FrameworkUtils.class,
                         Mockito.CALLS_REAL_METHODS);
                 MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
                 MockedStatic<OAuth2Util.OAuthURL> oAuthURL = mockStatic(OAuth2Util.OAuthURL.class);
                 MockedStatic<AuthorizationHandlerManager> authorizationHandlerManager =
                         mockStatic(AuthorizationHandlerManager.class);
                 MockedStatic<OpenIDConnectUserRPStore> openIDConnectUserRPStore =
                         mockStatic(OpenIDConnectUserRPStore.class);
                 MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class,
                         Mockito.CALLS_REAL_METHODS);
                 MockedStatic<ServiceURLBuilder> serviceURLBuilder = mockStatic(ServiceURLBuilder.class);
                 MockedStatic<EndpointUtil> endpointUtil = mockStatic(EndpointUtil.class, Mockito.CALLS_REAL_METHODS);
                 MockedStatic<OAuth2ServiceFactory> oAuth2ServiceFactory = mockStatic(OAuth2ServiceFactory.class);
                 MockedStatic<Oauth2ScopeServiceFactory> oAuth2ScopeServiceFactory =
                         mockStatic(Oauth2ScopeServiceFactory.class);
                 MockedStatic<OAuth2ServiceComponentHolder> serviceComponentHolder =
                         mockStatic(OAuth2ServiceComponentHolder.class, Mockito.CALLS_REAL_METHODS)) {

                oAuth2ScopeServiceFactory.when(Oauth2ScopeServiceFactory::getOAuth2ScopeService)
                        .thenReturn(oAuth2ScopeService);
                sessionDataCache.when(SessionDataCache::getInstance).thenReturn(mockSessionDataCache);
                SessionDataCacheKey loginDataCacheKey = new SessionDataCacheKey(SESSION_DATA_KEY_VALUE);
                when(mockSessionDataCache.getValueFromCache(loginDataCacheKey)).thenReturn(loginCacheEntry);
                loggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(diagnosticLogsEnabled);

                AuthenticationResult result =
                        setAuthenticationResult(isAuthenticated, attributes, errorCode, errorMsg, errorUri);

                AuthenticationResult resultInRequest = null;
                AuthenticationResultCacheEntry authResultCacheEntry = null;
                if (isResultInRequest) {
                    resultInRequest = result;
                } else {
                    authResultCacheEntry = new AuthenticationResultCacheEntry();
                    authResultCacheEntry.setResult(result);
                }

                Map<String, String[]> requestParams = new HashMap<>();
                Map<String, Object> requestAttributes = new HashMap<>();

                requestParams.put(CLIENT_ID, new String[]{CLIENT_ID_VALUE});
                requestParams.put(FrameworkConstants.RequestParams.TO_COMMONAUTH, new String[]{"false"});
                requestParams.put(OAuthConstants.OAuth20Params.SCOPE, new String[]{OAuthConstants.Scope.OPENID});

                requestAttributes.put(FrameworkConstants.RequestParams.FLOW_STATUS, AuthenticatorFlowStatus.INCOMPLETE);
                requestAttributes.put(FrameworkConstants.SESSION_DATA_KEY, SESSION_DATA_KEY_VALUE);
                requestAttributes.put(FrameworkConstants.RequestAttribute.AUTH_RESULT, resultInRequest);

                mockHttpRequest(requestParams, requestAttributes, HttpMethod.POST);

                frameworkUtils.when(FrameworkUtils::getRequestCoordinator).thenReturn(requestCoordinator);
                frameworkUtils.when(() -> FrameworkUtils.startTenantFlow(anyString())).thenAnswer(invocation -> null);
                frameworkUtils.when(FrameworkUtils::endTenantFlow).thenAnswer(invocation -> null);
                frameworkUtils.when(() -> FrameworkUtils.resolveUserIdFromUsername(anyInt(), anyString(), anyString()))
                        .thenReturn("sample");

                identityUtil.when(() -> IdentityUtil.getServerURL(anyString(), anyBoolean(), anyBoolean()))
                        .thenReturn("https://localhost:9443/carbon");

                OAuth2Parameters oAuth2Params =
                        setOAuth2Parameters(scopes, APP_NAME, responseMode, redirectUri, testAuthorizationDetails);
                oAuth2Params.setClientId(CLIENT_ID_VALUE);
                oAuth2Params.setState(STATE);
                when(loginCacheEntry.getoAuth2Parameters()).thenReturn(oAuth2Params);
                when(loginCacheEntry.getLoggedInUser()).thenReturn(result.getSubject());

                identityTenantUtil.when(() -> IdentityTenantUtil.getTenantDomain(anyInt()))
                        .thenReturn(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
                identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString()))
                        .thenReturn(MultitenantConstants.SUPER_TENANT_ID);
                identityTenantUtil.when(IdentityTenantUtil::getLoginTenantId)
                        .thenReturn(MultitenantConstants.SUPER_TENANT_ID);

                oAuthURL.when(OAuth2Util.OAuthURL::getOAuth2ErrorPageUrl).thenReturn(ERROR_PAGE_URL);

                authorizationHandlerManager.when(
                        AuthorizationHandlerManager::getInstance).thenReturn(mockAuthorizationHandlerManager);

                OAuth2AuthorizeReqDTO authzReqDTO = new OAuth2AuthorizeReqDTO();
                authzReqDTO.setConsumerKey(CLIENT_ID_VALUE);
                authzReqDTO.setScopes(new String[]{OAuthConstants.Scope.OPENID});
                authzReqDTO.setCallbackUrl(redirectUri);
                authzReqDTO.setUser(loginCacheEntry.getLoggedInUser());
                authzReqDTO.setResponseType("code");
                OAuthAuthzReqMessageContext authzReqMsgCtx = new OAuthAuthzReqMessageContext(authzReqDTO);
                authzReqMsgCtx.setApprovedScope(new String[]{OAuthConstants.Scope.OPENID});
                authzReqMsgCtx.setApprovedAuthorizationDetails(new AuthorizationDetails(testAuthorizationDetails));
                when(oAuth2Service.validateScopesBeforeConsent(any(OAuth2AuthorizeReqDTO.class))).thenReturn(
                        authzReqMsgCtx);
                when(mockAuthorizationHandlerManager.validateScopesBeforeConsent(any(OAuth2AuthorizeReqDTO.class)))
                        .thenReturn(authzReqMsgCtx);

                when(loginCacheEntry.getAuthzReqMsgCtx()).thenReturn(authzReqMsgCtx);

                openIDConnectUserRPStore.when(
                        OpenIDConnectUserRPStore::getInstance).thenReturn(mockOpenIDConnectUserRPStore);
                when(mockOpenIDConnectUserRPStore.hasUserApproved(any(AuthenticatedUser.class), anyString(),
                        anyString())).
                        thenReturn(true);

                mockEndpointUtil(false, endpointUtil);
                oAuth2ServiceFactory.when(OAuth2ServiceFactory::getOAuth2Service).thenReturn(oAuth2Service);
                when(oAuth2Service.getOauthApplicationState(CLIENT_ID_VALUE)).thenReturn("ACTIVE");

                mockApplicationManagementService();

                when(oAuth2Service.handleAuthenticationFailure(oAuth2Params)).thenReturn(oAuthErrorDTO);
                when(oAuth2ScopeService.hasUserProvidedConsentForAllRequestedScopes(
                        anyString(), isNull(), anyInt(), anyList())).thenReturn(true);

                when(authorizationDetailsServiceMock.isUserAlreadyConsentedForAuthorizationDetails(
                        any(AuthenticatedUser.class), any(OAuth2Parameters.class))).thenReturn(true);

                when(authorizationDetailsValidatorMock
                        .getValidatedAuthorizationDetails(any(OAuthAuthzReqMessageContext.class)))
                        .thenReturn(new AuthorizationDetails(testAuthorizationDetails));

                OAuth2ServiceComponentHolder.getInstance()
                        .setAuthorizationDetailsService(authorizationDetailsServiceMock);
                OAuth2ServiceComponentHolder.getInstance()
                        .setAuthorizationDetailsValidator(authorizationDetailsValidatorMock);

                mockServiceURLBuilder(serviceURLBuilder);
                setSupportedResponseModes();
                Response response = oAuth2AuthzEndpoint.authorize(httpServletRequest, httpServletResponse);
                assertEquals(response.getStatus(), expected, "Unexpected HTTP response status");
                if (!isAuthenticated) {
                    String expectedState =
                            "name=\"" + OAuthConstants.OAuth20Params.STATE + "\" value=\"" + STATE + "\"";
                    assertTrue(response.getEntity().toString().contains(expectedState));
                }
            }
        }
    }

    @DataProvider(name = "provideConsentData")
    public Object[][] provideConsentData() {

        return addDiagnosticLogStatusToExistingDataProvider(new Object[][]{
                {null, APP_REDIRECT_URL, new HashSet<>(Arrays.asList(OAuthConstants.Scope.OPENID)),
                        HttpServletResponse.SC_FOUND, null, OAuth2ErrorCodes.INVALID_REQUEST},

                {"deny", APP_REDIRECT_URL, new HashSet<>(Arrays.asList(OAuthConstants.Scope.OPENID)),
                        HttpServletResponse.SC_OK, null, OAuth2ErrorCodes.ACCESS_DENIED},

                {"deny", APP_REDIRECT_URL, new HashSet<>(Arrays.asList("scope1")), HttpServletResponse.SC_OK, null,
                        OAuth2ErrorCodes.ACCESS_DENIED},

                {"deny", APP_REDIRECT_URL, new HashSet<>(Arrays.asList("scope1")), HttpServletResponse.SC_OK,
                        "User denied the consent", OAuth2ErrorCodes.ACCESS_DENIED},

                {"approve", APP_REDIRECT_URL, new HashSet<>(Arrays.asList(OAuthConstants.Scope.OPENID)),
                        HttpServletResponse.SC_FOUND, null, null},

                {"approve", APP_REDIRECT_URL, new HashSet<>(Arrays.asList("scope1")),
                        HttpServletResponse.SC_FOUND, null, null},

                {"approve", APP_REDIRECT_URL_JSON, new HashSet<>(Arrays.asList(OAuthConstants.Scope.OPENID)),
                        HttpServletResponse.SC_OK, null, null},

                {"approve", APP_REDIRECT_URL_JSON, new HashSet<>(Arrays.asList("scope1")),
                        HttpServletResponse.SC_OK, null, null},
        });
    }

    @DataProvider(name = "provideRequestObject")
    public Object[][] provideRequestObject() {

        List<String> claimValues = Arrays.asList("test", "test1", "test2");
        String claimValue = "test";

        RequestObject requestObjectWithValue = new RequestObject();
        Map<String, List<RequestedClaim>> claimsforRequestParameter = new HashMap<>();
        RequestedClaim requestedClaim = new RequestedClaim();
        requestedClaim.setName(OAuthConstants.ACR);
        requestedClaim.setValue(claimValue);
        requestedClaim.setEssential(true);
        claimsforRequestParameter.put(OIDCConstants.ID_TOKEN, Collections.singletonList(requestedClaim));
        requestObjectWithValue.setRequestedClaims(claimsforRequestParameter);

        RequestObject requestObjectWithValues = new RequestObject();
        requestedClaim = new RequestedClaim();
        requestedClaim.setName(OAuthConstants.ACR);
        requestedClaim.setEssential(true);
        claimsforRequestParameter = new HashMap<>();
        requestedClaim.setValues(claimValues);
        claimsforRequestParameter.put(OIDCConstants.ID_TOKEN, Collections.singletonList(requestedClaim));
        requestObjectWithValues.setRequestedClaims(claimsforRequestParameter);

        return new Object[][]{
                {null, null},
                {new RequestObject(), null},
                {requestObjectWithValue, Collections.singletonList(claimValue)},
                {requestObjectWithValues, claimValues}
        };
    }

    @Test(dataProvider = "provideRequestObject", description = "This test case tests the flow when the request object"
            + " includes acr claims")
    public void testGetAcrValues(Object requestObject, List<String> expectedAcrValues) throws NoSuchMethodException,
            InvocationTargetException, IllegalAccessException {

        Method method = authzEndpointObject.getClass().getDeclaredMethod("getAcrValues", RequestObject.class);
        method.setAccessible(true);
        Object acrValues = method.invoke(authzEndpointObject, requestObject);
        Assert.assertEquals(acrValues, expectedAcrValues, "Actual ACR values does not match with expected ACR values");
    }

    @Test(dataProvider = "provideConsentData", groups = "testWithConnection")
    public void testUserConsentResponse(String consent, String redirectUrl, Set<String> scopes,
                                        int expectedStatus, String oAuthErrorDTODescription, String expectedError,
                                        boolean diagnosticLogsEnabled)
            throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class)) {
            mockSSOConsentService(true);
            mockOAuthServerConfiguration(oAuthServerConfiguration);
            try (MockedStatic<FrameworkUtils> frameworkUtils = mockStatic(FrameworkUtils.class);
                 MockedStatic<LoggerUtils> loggerUtils = mockStatic(LoggerUtils.class);
                 MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
                 MockedStatic<ClaimMetadataHandler> claimMetadataHandler = mockStatic(ClaimMetadataHandler.class);
                 MockedStatic<SessionDataCache> sessionDataCache = mockStatic(SessionDataCache.class);
                 MockedStatic<OAuth2Util.OAuthURL> oAuthURL = mockStatic(OAuth2Util.OAuthURL.class);
                 MockedStatic<OpenIDConnectUserRPStore> openIDConnectUserRPStore =
                         mockStatic(OpenIDConnectUserRPStore.class);
                 MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class, Mockito.CALLS_REAL_METHODS);
                 MockedStatic<EndpointUtil> endpointUtil =
                         mockStatic(EndpointUtil.class, Mockito.CALLS_REAL_METHODS);) {

                when(authCookie.getValue()).thenReturn("dummyValue");
                frameworkUtils.when(() -> FrameworkUtils.getAuthCookie(any())).thenReturn(authCookie);
                frameworkUtils.when(() -> FrameworkUtils.startTenantFlow(anyString())).thenAnswer(invocation -> null);
                frameworkUtils.when(FrameworkUtils::endTenantFlow).thenAnswer(invocation -> null);
                loggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(diagnosticLogsEnabled);
                identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString()))
                        .thenReturn(MultitenantConstants.SUPER_TENANT_ID);

                SessionContext sessionContext = new SessionContext();
                sessionContext.addProperty(FrameworkConstants.CREATED_TIMESTAMP, 1479249799770L);

                frameworkUtils.when(() -> FrameworkUtils.getSessionContextFromCache(anyString(), anyString()))
                        .thenReturn(sessionContext);

                when(openIDConnectClaimFilter.getClaimsFilteredByOIDCScopes(any(), anyString())).thenReturn(
                        Arrays.asList(
                                "country"));

                Set<ExternalClaim> mappings = new HashSet<>();
                ExternalClaim claim = new ExternalClaim(OIDC_DIALECT, "country", "http://wso2.org/country");
                mappings.add(claim);
                when(mockClaimMetadataHandler.getMappingsFromOtherDialectToCarbon(anyString(), any(), anyString()))
                        .thenReturn(mappings);

                claimMetadataHandler.when(ClaimMetadataHandler::getInstance).thenReturn(this.mockClaimMetadataHandler);

                sessionDataCache.when(SessionDataCache::getInstance).thenReturn(mockSessionDataCache);
                SessionDataCacheKey consentDataCacheKey = new SessionDataCacheKey(SESSION_DATA_KEY_CONSENT_VALUE);
                when(mockSessionDataCache.getValueFromCache(consentDataCacheKey)).thenReturn(consentCacheEntry);

                Map<String, String[]> requestParams = new HashMap<>();
                Map<String, Object> requestAttributes = new ConcurrentHashMap<>();

                requestParams.put(OAuthConstants.SESSION_DATA_KEY_CONSENT,
                        new String[]{SESSION_DATA_KEY_CONSENT_VALUE});
                requestParams.put(FrameworkConstants.RequestParams.TO_COMMONAUTH, new String[]{"false"});
                requestParams.put(OAuthConstants.OAuth20Params.SCOPE, new String[]{OAuthConstants.Scope.OPENID});
                requestParams.put(OAuthConstants.Prompt.CONSENT, new String[]{consent});
                requestParams.put(CLIENT_ID, new String[]{CLIENT_ID_VALUE});

                requestAttributes.put(FrameworkConstants.RequestParams.FLOW_STATUS, AuthenticatorFlowStatus.INCOMPLETE);

                mockHttpRequest(requestParams, requestAttributes, HttpMethod.POST);

                OAuth2Parameters oAuth2Params =
                        setOAuth2Parameters(scopes, APP_NAME, RESPONSE_MODE_FORM_POST, redirectUrl, null);
                oAuth2Params.setClientId(CLIENT_ID_VALUE);

                when(consentCacheEntry.getoAuth2Parameters()).thenReturn(oAuth2Params);
                when(consentCacheEntry.getLoggedInUser()).thenReturn(new AuthenticatedUser());

                OAuth2AuthorizeReqDTO authorizeReqDTO = new OAuth2AuthorizeReqDTO();
                OAuthAuthzReqMessageContext authzReqMsgCtx = new OAuthAuthzReqMessageContext(authorizeReqDTO);
                when(consentCacheEntry.getAuthzReqMsgCtx()).thenReturn(authzReqMsgCtx);

                openIDConnectUserRPStore.when(OpenIDConnectUserRPStore::getInstance)
                        .thenReturn(mockOpenIDConnectUserRPStore);
                doNothing().when(mockOpenIDConnectUserRPStore).putUserRPToStore(any(AuthenticatedUser.class),
                        anyString(), anyBoolean(), anyString());


                oAuthURL.when(OAuth2Util.OAuthURL::getOAuth2ErrorPageUrl).thenReturn(ERROR_PAGE_URL);
                oAuth2Util.when(() -> OAuth2Util.getServiceProvider(CLIENT_ID_VALUE)).thenReturn(new ServiceProvider());

                mockEndpointUtil(true, endpointUtil);
                when(oAuth2Service.getOauthApplicationState(CLIENT_ID_VALUE)).thenReturn("ACTIVE");

                mockApplicationManagementService();

                when(oAuth2Service.handleUserConsentDenial(oAuth2Params)).thenReturn(oAuthErrorDTO);

                when(oAuthErrorDTO.getErrorDescription()).thenReturn(oAuthErrorDTODescription);

                Response response;
                try {
                    setSupportedResponseModes();
                    response = oAuth2AuthzEndpoint.authorize(httpServletRequest, httpServletResponse);
                } catch (InvalidRequestParentException ire) {
                    InvalidRequestExceptionMapper invalidRequestExceptionMapper = new InvalidRequestExceptionMapper();
                    response = invalidRequestExceptionMapper.toResponse(ire);
                }

                if (response != null) {
                    assertEquals(response.getStatus(), expectedStatus, "Unexpected HTTP response status");

                    MultivaluedMap<String, Object> responseMetadata = response.getMetadata();
                    assertNotNull(responseMetadata);

                    if (expectedError != null) {
                        if (response.getEntity() != null) {
                            String htmlPost = response.getEntity().toString();
                            assertTrue(htmlPost.contains(expectedError));
                        } else {
                            CollectionUtils.isNotEmpty(responseMetadata.get(HTTPConstants.HEADER_LOCATION));
                            assertTrue(CollectionUtils.isNotEmpty(responseMetadata.get(HTTPConstants.HEADER_LOCATION)),
                                    "Location header not found in the response");
                            String location =
                                    String.valueOf(responseMetadata.get(HTTPConstants.HEADER_LOCATION).get(0));
                            assertTrue(location.contains(expectedError), "Expected error code not found in URL");
                        }
                    }
                }
            }
        }
    }

    @DataProvider(name = "provideAuthzRequestData")
    public Object[][] provideAuthzRequestData() {

        String validPKCEChallenge = "abcdef1234A46gfdhhjhnmvmu764745463565nnnvbnn6";
        return addDiagnosticLogStatusToExistingDataProvider(new Object[][]{
                // Authz request from Valid client, PKCE not enabled. request sent to framework for authentication
                {CLIENT_ID_VALUE, APP_REDIRECT_URL, null, null, null, true, false, true, LOGIN_PAGE_URL},

                // Blank client ID is received. Redirected to error page with invalid_request error
                {"", APP_REDIRECT_URL, null, null, null, true, false, true, ERROR_PAGE_URL},

                // Valid client, ACR url null, PKCE not enabled. request sent to framework for authentication
                {CLIENT_ID_VALUE, null, null, null, null, true, false, true, LOGIN_PAGE_URL},

                // Valid client, ACR value is "null". Correctly considers it as a null ACR.
                // PKCE not enabled. Request sent to framework for authentication
                {CLIENT_ID_VALUE, "null", null, null, null, true, false, true, LOGIN_PAGE_URL},

                // Invalid client. Redirected to error page.
                {CLIENT_ID_VALUE, APP_REDIRECT_URL, null, null, null, false, false, true, ERROR_PAGE_URL},

                // Valid client, PKCE is enabled and mandatory, PKCE code is null.
                // Redirected to error page with invalid_request error
                {CLIENT_ID_VALUE, APP_REDIRECT_URL, null, null, null, true, true, true, ERROR_PAGE_URL},

                // Valid client, PKCE is enabled but not mandatory, PKCE code is null.
                // Request sent to framework for authentication
                {CLIENT_ID_VALUE, APP_REDIRECT_URL, null, null, null, true, true, false, LOGIN_PAGE_URL},

                // Valid client, PKCE is enabled and mandatory, valid PKCE code, plain PKCE challenge method,
                // plain PKCE is supported. Request sent to framework for authentication
                {CLIENT_ID_VALUE, APP_REDIRECT_URL, validPKCEChallenge, OAuthConstants.OAUTH_PKCE_PLAIN_CHALLENGE, null,
                        true, true, true, LOGIN_PAGE_URL},

                // Valid client, PKCE is enabled and mandatory, invalid PKCE code, plain PKCE challenge method,
                // plain PKCE is supported. Redirected to error page with invalid_request error
                {CLIENT_ID_VALUE, APP_REDIRECT_URL, "dummmyPkceChallenge", OAuthConstants.OAUTH_PKCE_PLAIN_CHALLENGE,
                        null, true, true, true, ERROR_PAGE_URL},

                // Valid client, PKCE is enabled but not mandatory, valid plain PKCE code, un supported PKCE
                // challenge method, plain PKCE is not supported. Redirected to error page with invalid_request error
                {CLIENT_ID_VALUE, APP_REDIRECT_URL, validPKCEChallenge, "invalidMethod", null, true, true, false,
                        ERROR_PAGE_URL},

                // Valid client, PKCE is enabled but not mandatory, valid plain PKCE code, plain PKCE challenge method,
                // plain PKCE is not supported. Redirected to error page with invalid_request error
                {CLIENT_ID_VALUE, APP_REDIRECT_URL, validPKCEChallenge, OAuthConstants.OAUTH_PKCE_PLAIN_CHALLENGE, null,
                        true, true, false, ERROR_PAGE_URL},

                // Valid client, PKCE is enabled but not mandatory, valid plain PKCE code, PKCE challenge method is
                // null plain PKCE is not supported. Redirected to error page with invalid_request error
                {CLIENT_ID_VALUE, APP_REDIRECT_URL, validPKCEChallenge, null, null, true, true, false, ERROR_PAGE_URL},

                // Valid client, PKCE is enabled but not mandatory, valid plain PKCE code, PKCE challenge method is
                // s256, plain PKCE is not supported. Redirected to error page with invalid_request error
                {CLIENT_ID_VALUE, APP_REDIRECT_URL, validPKCEChallenge, OAuthConstants.OAUTH_PKCE_S256_CHALLENGE, null,
                        true, true, false, ERROR_PAGE_URL},

                // Valid client, prompt is "none", PKCE not supported. Request sent to framework for authentication
                // since user is not authenticated
                {CLIENT_ID_VALUE, APP_REDIRECT_URL, null, null, OAuthConstants.Prompt.NONE, true, false, true,
                        LOGIN_PAGE_URL},

                // Valid client, prompt is "consent" and "login", PKCE not supported.
                // Request sent to framework for authentication
                {CLIENT_ID_VALUE, APP_REDIRECT_URL, null, null, OAuthConstants.Prompt.CONSENT + " " +
                        OAuthConstants.Prompt.LOGIN, true, false, true, LOGIN_PAGE_URL},

                // Valid client, prompt is "login", PKCE not supported. Request sent to framework for authentication
                {CLIENT_ID_VALUE, APP_REDIRECT_URL, null, null, OAuthConstants.Prompt.SELECT_ACCOUNT + " " +
                        OAuthConstants.Prompt.LOGIN, true, false, true, LOGIN_PAGE_URL},

                // Valid client, prompt is "consent" and "select_account", PKCE not supported.
                // Request sent to framework for authentication
                {CLIENT_ID_VALUE, APP_REDIRECT_URL, null, null, OAuthConstants.Prompt.SELECT_ACCOUNT + " " +
                        OAuthConstants.Prompt.CONSENT, true, false, true, LOGIN_PAGE_URL},

                // Valid client, prompt is "none" and "login", PKCE not supported.
                // Redirected to application with invalid_request error
                {CLIENT_ID_VALUE, APP_REDIRECT_URL, null, null, OAuthConstants.Prompt.NONE + " " +
                        OAuthConstants.Prompt.LOGIN, true, false, true, APP_REDIRECT_URL},

                // Valid client, unsupported prompt, PKCE not supported.
                // Redirected to application with invalid_request error
                {CLIENT_ID_VALUE, APP_REDIRECT_URL, null, null, "dummyPrompt", true, false, true, APP_REDIRECT_URL},

                // Valid client, prompt is "login", PKCE not supported. Request sent to framework for authentication
                {CLIENT_ID_VALUE, APP_REDIRECT_URL, null, null, OAuthConstants.Prompt.LOGIN, true, false, true,
                        LOGIN_PAGE_URL},

                // Valid client, prompt is "consent", PKCE not supported. Request sent to framework for authentication
                {CLIENT_ID_VALUE, APP_REDIRECT_URL, null, null, OAuthConstants.Prompt.CONSENT, true, false, true,
                        LOGIN_PAGE_URL},

                // Valid client, prompt is "select_account", PKCE not supported.
                // Request sent to framework for authentication
                {CLIENT_ID_VALUE, APP_REDIRECT_URL, null, null, OAuthConstants.Prompt.SELECT_ACCOUNT, true, false, true,
                        LOGIN_PAGE_URL},

                // Special data manipulation. For this combination of inputs, EndpointUtil.getLoginPageURL() is set to
                // throw a IdentityOAuth2Exception.
                // Redirected to error page with invalid_request error because of the exception

                // Temporarily disabled
                // {CLIENT_ID_VALUE, APP_REDIRECT_URL, null, null, OAuthConstants.Prompt.NONE, true, false, true,
                // ERROR_PAGE_URL},
        });
    }

    /**
     * Tests the scenario of authorization request from the client
     */
    @Test(dataProvider = "provideAuthzRequestData", groups = "testWithConnection")
    public void testHandleOAuthAuthorizationRequest(String clientId, String redirectUri, String pkceChallengeCode,
                                                    String pkceChallengeMethod, String prompt, boolean clientValid,
                                                    boolean pkceEnabled, boolean supportPlainPkce,
                                                    String expectedLocation, boolean diagnosticLogsEnabled)
            throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class)) {
            mockSSOConsentService(false);
            mockOAuthServerConfiguration(oAuthServerConfiguration);
            try (MockedStatic<FrameworkUtils> frameworkUtils = mockStatic(FrameworkUtils.class,
                    Mockito.CALLS_REAL_METHODS);
                 MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
                 MockedStatic<LoggerUtils> loggerUtils = mockStatic(LoggerUtils.class);
                 MockedStatic<CentralLogMgtServiceComponentHolder> centralLogMgtServiceComponentHolder =
                         mockStatic(CentralLogMgtServiceComponentHolder.class);
                 MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class);
                 MockedStatic<OAuth2Util.OAuthURL> oAuthURL = mockStatic(OAuth2Util.OAuthURL.class);
                 MockedStatic<ServiceURLBuilder> serviceURLBuilder = mockStatic(ServiceURLBuilder.class);
                 MockedStatic<EndpointUtil> endpointUtil = mockStatic(EndpointUtil.class, Mockito.CALLS_REAL_METHODS);
                 MockedStatic<OAuth2ServiceFactory> oAuth2ServiceFactory = mockStatic(OAuth2ServiceFactory.class);) {

                oAuth2ServiceFactory.when(OAuth2ServiceFactory::getOAuth2Service).thenReturn(oAuth2Service);
                Map<String, String[]> requestParams = new HashMap();
                Map<String, Object> requestAttributes = new HashMap();

                requestParams.put(CLIENT_ID, new String[]{clientId});

                // No consent data is saved in the cache yet and client doesn't send cache key
                requestParams.put(OAuthConstants.SESSION_DATA_KEY_CONSENT, new String[]{null});
                requestParams.put(FrameworkConstants.RequestParams.TO_COMMONAUTH, new String[]{"false"});
                requestParams.put(REDIRECT_URI, new String[]{APP_REDIRECT_URL});
                requestParams.put(OAuthConstants.OAUTH_PKCE_CODE_CHALLENGE, new String[]{pkceChallengeCode});
                requestParams.put(OAuthConstants.OAUTH_PKCE_CODE_CHALLENGE_METHOD, new String[]{pkceChallengeMethod});
                requestParams.put(OAuth.OAUTH_RESPONSE_TYPE, new String[]{ResponseType.TOKEN.toString()});
                if (redirectUri != null) {
                    requestParams.put("acr_values", new String[]{redirectUri});
                    requestParams.put("claims", new String[]{"essentialClaims"});
                    requestParams.put(MultitenantConstants.TENANT_DOMAIN,
                            new String[]{MultitenantConstants.SUPER_TENANT_DOMAIN_NAME});
                }
                requestAttributes.put(FrameworkConstants.RequestParams.FLOW_STATUS, AuthenticatorFlowStatus.INCOMPLETE);
                // No authentication data is saved in the cache yet and client doesn't send cache key
                requestAttributes.put(FrameworkConstants.SESSION_DATA_KEY, null);

                if (prompt != null) {
                    requestParams.put(OAuthConstants.OAuth20Params.PROMPT, new String[]{prompt});
                }

                boolean checkErrorCode = ERROR_PAGE_URL.equals(expectedLocation);
                mockHttpRequest(requestParams, requestAttributes, HttpMethod.POST);

                Map<String, Class<? extends OAuthValidator<HttpServletRequest>>> responseTypeValidators =
                        new Hashtable<>();
                responseTypeValidators.put(ResponseType.CODE.toString(), CodeValidator.class);
                responseTypeValidators.put(ResponseType.TOKEN.toString(), TokenValidator.class);

                when(mockOAuthServerConfiguration.getSupportedResponseTypeValidators()).thenReturn(
                        responseTypeValidators);

                frameworkUtils.when(() -> FrameworkUtils.startTenantFlow(anyString())).thenAnswer(invocation -> null);
                frameworkUtils.when(FrameworkUtils::endTenantFlow).thenAnswer(invocation -> null);
                identityTenantUtil.when(() -> IdentityTenantUtil.getTenantDomain(anyInt()))
                        .thenReturn(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
                identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString()))
                        .thenReturn(MultitenantConstants.SUPER_TENANT_ID);
                loggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(diagnosticLogsEnabled);
                IdentityEventService eventServiceMock = mock(IdentityEventService.class);

                centralLogMgtServiceComponentHolder.when(
                                CentralLogMgtServiceComponentHolder::getInstance)
                        .thenReturn(centralLogMgtServiceComponentHolderMock);
                when(centralLogMgtServiceComponentHolderMock.getIdentityEventService()).thenReturn(eventServiceMock);
                doNothing().when(eventServiceMock).handleEvent(any());

                mockEndpointUtil(false, endpointUtil);
                when(oAuth2Service.getOauthApplicationState(CLIENT_ID_VALUE)).thenReturn("ACTIVE");
                when(oAuth2Service.isPKCESupportEnabled()).thenReturn(pkceEnabled);
                if (ERROR_PAGE_URL.equals(expectedLocation) && OAuthConstants.Prompt.NONE.equals(prompt)) {
                    endpointUtil.when(() -> EndpointUtil.getLoginPageURL(anyString(),
                                    anyString(), anyBoolean(), anyBoolean(), anySet(), anyMap(), any()))
                            .thenThrow(new IdentityOAuth2Exception("error"));

                    checkErrorCode = false;
                }

                oAuth2Util.when(() -> OAuth2Util.validatePKCECodeChallenge(anyString(), anyString()))
                        .thenCallRealMethod();
                oAuth2Util.when(() -> OAuth2Util.validatePKCECodeVerifier(anyString())).thenCallRealMethod();
                oAuthURL.when(OAuth2Util.OAuthURL::getOAuth2ErrorPageUrl).thenReturn(ERROR_PAGE_URL);

                OAuth2ClientValidationResponseDTO validationResponseDTO = new OAuth2ClientValidationResponseDTO();
                validationResponseDTO.setValidClient(clientValid);
                validationResponseDTO.setCallbackURL(APP_REDIRECT_URL);
                if (!clientValid) {
                    validationResponseDTO.setErrorCode(OAuth2ErrorCodes.INVALID_REQUEST);
                    validationResponseDTO.setErrorMsg("client is invalid");
                }
                OAuthAppDO oAuthAppDO = new OAuthAppDO();
                oAuthAppDO.setPkceMandatory(supportPlainPkce);
                oAuthAppDO.setPkceSupportPlain(supportPlainPkce);
                oAuth2Util.when(() -> OAuth2Util.getAppInformationByClientId(any())).thenReturn(oAuthAppDO);
                when(oAuth2Service.validateClientInfo(any())).thenReturn(validationResponseDTO);
                oAuth2Util.when(() -> OAuth2Util.getAppInformationByClientId(any(), any())).thenReturn(oAuthAppDO);

                try (MockedConstruction<CommonAuthenticationHandler> mockedConstruction = Mockito.mockConstruction(
                        CommonAuthenticationHandler.class,
                        (mock, context) -> {
                            if (StringUtils.equals(expectedLocation, LOGIN_PAGE_URL) ||
                                    StringUtils.equals(expectedLocation, ERROR_PAGE_URL)) {
                                doAnswer(invocation -> {

                                    CommonAuthRequestWrapper request =
                                            (CommonAuthRequestWrapper) invocation.getArguments()[0];
                                    request.setAttribute(FrameworkConstants.RequestParams.FLOW_STATUS,
                                            AuthenticatorFlowStatus.INCOMPLETE);

                                    CommonAuthResponseWrapper wrapper =
                                            (CommonAuthResponseWrapper) invocation.getArguments()[1];
                                    wrapper.sendRedirect(expectedLocation);
                                    return null;
                                }).when(mock).doGet(any(), any());
                            }
                        })) {

                    mockServiceURLBuilder(serviceURLBuilder);

                    Response response;
                    try {
                        response = oAuth2AuthzEndpoint.authorize(httpServletRequest, httpServletResponse);
                    } catch (InvalidRequestParentException ire) {
                        InvalidRequestExceptionMapper invalidRequestExceptionMapper =
                                new InvalidRequestExceptionMapper();
                        response = invalidRequestExceptionMapper.toResponse(ire);
                    }

                    assertNotNull(response);
                    assertEquals(response.getStatus(), HttpServletResponse.SC_FOUND, "Unexpected HTTP response status");

                    MultivaluedMap<String, Object> responseMetadata = response.getMetadata();
                    assertNotNull(responseMetadata, "Response metadata is null");

                    assertTrue(CollectionUtils.isNotEmpty(responseMetadata.get(HTTPConstants.HEADER_LOCATION)),
                            "Location header not found in the response");
                    String location = String.valueOf(responseMetadata.get(HTTPConstants.HEADER_LOCATION).get(0));
                    assertTrue(location.contains(expectedLocation), "Unexpected redirect url in the response");

                    if (checkErrorCode) {
                        assertTrue(location.contains(OAuth2ErrorCodes.INVALID_REQUEST),
                                "Expected error code not found in URL");
                    }
                }

            }
        }
    }

    @DataProvider(name = "provideRequestParams")
    public Object[][] provideRequestParams() {

        return addDiagnosticLogStatusToExistingDataProvider(new Object[][]{
                {AuthenticatorFlowStatus.SUCCESS_COMPLETED, "sample_scope", HttpServletResponse.SC_FOUND}
        });
    }

    @Test(dataProvider = "provideRequestParams", groups = "testWithConnection")
    public void testTestAuthorize(Object flowStatusObject, String scope, int expectedStatus,
                                  boolean diagnosticLogsEnabled) throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class)) {
            mockOAuthServerConfiguration(oAuthServerConfiguration);
            try (MockedStatic<FrameworkUtils> frameworkUtils = mockStatic(FrameworkUtils.class,
                    Mockito.CALLS_REAL_METHODS);
                 MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
                 MockedStatic<LoggerUtils> loggerUtils = mockStatic(LoggerUtils.class);
                 MockedStatic<CentralLogMgtServiceComponentHolder> centralLogMgtServiceComponentHolder =
                         mockStatic(CentralLogMgtServiceComponentHolder.class);
                 MockedStatic<OAuth2Util.OAuthURL> oAuthURL = mockStatic(OAuth2Util.OAuthURL.class);
                 MockedStatic<SessionDataCache> sessionDataCache = mockStatic(SessionDataCache.class);
                 MockedStatic<AuthorizationHandlerManager> authorizationHandlerManager =
                         mockStatic(AuthorizationHandlerManager.class);
                 MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class);
                 MockedStatic<EndpointUtil> endpointUtil = mockStatic(EndpointUtil.class,
                         Mockito.CALLS_REAL_METHODS);
                 MockedStatic<ServiceURLBuilder> serviceURLBuilder = mockStatic(ServiceURLBuilder.class);
                 MockedStatic<OAuth2ServiceFactory> oAuth2ServiceFactory = mockStatic(OAuth2ServiceFactory.class);
                 MockedStatic<Oauth2ScopeServiceFactory> oauth2ScopeServiceFactory = mockStatic(
                         Oauth2ScopeServiceFactory.class);) {

                oAuth2ServiceFactory.when(OAuth2ServiceFactory::getOAuth2Service).thenReturn(oAuth2Service);
                oauth2ScopeServiceFactory.when(Oauth2ScopeServiceFactory::getOAuth2ScopeService).thenReturn(
                        oAuth2ScopeService);
                Map<String, String[]> requestParams = new HashMap<>();
                Map<String, Object> requestAttributes = new HashMap<>();

                requestParams.put(CLIENT_ID, new String[]{CLIENT_ID_VALUE});
                requestParams.put(OAuthConstants.OAuth20Params.SCOPE, new String[]{scope});
                requestParams.put(OAuth.OAUTH_RESPONSE_TYPE, new String[]{SUBJECT_TOKEN});
                requestParams.put("requested_subject", new String[]{"8122e3de-0f3b-4b0e-a43a-d0c237451b7a"});
                requestParams.put(REDIRECT_URI, new String[]{APP_REDIRECT_URL});

                when(mockOAuthServerConfiguration.isOAuthResponseJspPageAvailable()).thenReturn(false);

                requestAttributes.put(FrameworkConstants.RequestParams.FLOW_STATUS,
                        (AuthenticatorFlowStatus) flowStatusObject);
                requestAttributes.put(FrameworkConstants.SESSION_DATA_KEY, SESSION_DATA_KEY_VALUE);
                requestParams.put(REDIRECT_URI, new String[]{APP_REDIRECT_URL});
                AuthenticationResult result = setAuthenticationResult(true, null, null,
                        null, null);
                result.getSubject().setAuthenticatedSubjectIdentifier("Impersonator");
                requestAttributes.put(FrameworkConstants.RequestAttribute.AUTH_RESULT, result);

                mockHttpRequest(requestParams, requestAttributes, HttpMethod.POST);

                oAuthURL.when(OAuth2Util.OAuthURL::getOAuth2ErrorPageUrl).thenReturn(ERROR_PAGE_URL);

                frameworkUtils.when(() -> FrameworkUtils.startTenantFlow(anyString())).thenAnswer(
                        invocation -> null);
                frameworkUtils.when(FrameworkUtils::endTenantFlow).thenAnswer(invocation -> null);
                loggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(diagnosticLogsEnabled);
                identityTenantUtil.when(() -> IdentityTenantUtil.getTenantDomain(anyInt())).thenReturn(
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
                identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString()))
                        .thenReturn(MultitenantConstants.SUPER_TENANT_ID);
                identityTenantUtil.when(IdentityTenantUtil::getLoginTenantId)
                        .thenReturn(MultitenantConstants.SUPER_TENANT_ID);
                IdentityEventService eventServiceMock = mock(IdentityEventService.class);
                centralLogMgtServiceComponentHolder.when(CentralLogMgtServiceComponentHolder::getInstance).thenReturn(
                        centralLogMgtServiceComponentHolderMock);
                when(centralLogMgtServiceComponentHolderMock.getIdentityEventService()).thenReturn(eventServiceMock);
                doNothing().when(eventServiceMock).handleEvent(any());

                when(httpServletRequest.getServletContext()).thenReturn(servletContext);
                when(servletContext.getContext(anyString())).thenReturn(servletContext);
                when(servletContext.getRequestDispatcher(anyString())).thenReturn(requestDispatcher);
                doNothing().when(requestDispatcher).forward(any(ServletRequest.class), any(ServletResponse.class));

                OAuth2Parameters oAuth2Parameters = new OAuth2Parameters();
                oAuth2Parameters.setApplicationName(APP_NAME);
                oAuth2Parameters.setRedirectURI(APP_REDIRECT_URL);
                oAuth2Parameters.setScopes(Collections.singleton(scope));
                oAuth2Parameters.setResponseType(SUBJECT_TOKEN);
                oAuth2Parameters.setClientId(CLIENT_ID_VALUE);
                oAuth2Parameters.setSessionDataKey(SESSION_DATA_KEY_VALUE);
                oAuth2Parameters.setRequestedSubjectId("8122e3de-0f3b-4b0e-a43a-d0c237451b7a");

                sessionDataCache.when(SessionDataCache::getInstance).thenReturn(mockSessionDataCache);
                SessionDataCacheKey loginDataCacheKey = new SessionDataCacheKey(SESSION_DATA_KEY_VALUE);
                SessionDataCacheKey consentDataCacheKey = new SessionDataCacheKey(SESSION_DATA_KEY_CONSENT_VALUE);
                when(mockSessionDataCache.getValueFromCache(loginDataCacheKey)).thenReturn(loginCacheEntry);
                when(mockSessionDataCache.getValueFromCache(consentDataCacheKey)).thenReturn(consentCacheEntry);
                when(loginCacheEntry.getoAuth2Parameters()).thenReturn(oAuth2Parameters);
                when(loginCacheEntry.getLoggedInUser()).thenReturn(result.getSubject());

                authorizationHandlerManager.when(
                        AuthorizationHandlerManager::getInstance).thenReturn(mockAuthorizationHandlerManager);

                OAuth2AuthorizeReqDTO authzReqDTO = new OAuth2AuthorizeReqDTO();
                authzReqDTO.setConsumerKey(CLIENT_ID_VALUE);
                authzReqDTO.setScopes(new String[]{scope});
                authzReqDTO.setUser(loginCacheEntry.getLoggedInUser());
                authzReqDTO.setResponseType(SUBJECT_TOKEN);
                OAuthAuthzReqMessageContext authzReqMsgCtx = new OAuthAuthzReqMessageContext(authzReqDTO);
                authzReqMsgCtx.setApprovedScope(new String[]{scope});
                when(oAuth2Service.validateScopesBeforeConsent(any(OAuth2AuthorizeReqDTO.class))).thenReturn(
                        authzReqMsgCtx);
                when(mockAuthorizationHandlerManager.validateScopesBeforeConsent(any(OAuth2AuthorizeReqDTO.class)))
                        .thenReturn(authzReqMsgCtx);
                when(loginCacheEntry.getAuthzReqMsgCtx()).thenReturn(authzReqMsgCtx);

                when(oAuth2ScopeService.hasUserProvidedConsentForAllRequestedScopes(
                        anyString(), isNull(), anyInt(), anyList())).thenReturn(true);
                oAuth2Util.when(() -> OAuth2Util.getServiceProvider(CLIENT_ID_VALUE)).thenReturn(new ServiceProvider());
                when(mockOAuthServerConfiguration.getOpenIDConnectSkipeUserConsentConfig()).thenReturn(true);

                OAuth2AuthorizeRespDTO authzRespDTO = new OAuth2AuthorizeRespDTO();
                authzRespDTO.setCallbackURI(APP_REDIRECT_URL);
                authzRespDTO.setSubjectToken("sample_subject_token");
                when(oAuth2Service.authorize(any(OAuthAuthzReqMessageContext.class))).thenReturn(authzRespDTO);

                OAuth2ServiceComponentHolder.getInstance()
                        .setAuthorizationDetailsService(authorizationDetailsServiceMock);
                when(authorizationDetailsServiceMock.isUserAlreadyConsentedForAuthorizationDetails(
                        any(AuthenticatedUser.class), any(OAuth2Parameters.class))).thenReturn(true);

                mockEndpointUtil(false, endpointUtil);
                Response response;
                try (Connection connection = getConnection()) {
                    identityDatabaseUtil.when(IdentityDatabaseUtil::getDBConnection).thenReturn(connection);
                    mockServiceURLBuilder(serviceURLBuilder);
                    try {
                        setSupportedResponseModes();
                        response = oAuth2AuthzEndpoint.authorize(httpServletRequest, httpServletResponse);
                    } catch (InvalidRequestParentException ire) {
                        InvalidRequestExceptionMapper invalidRequestExceptionMapper =
                                new InvalidRequestExceptionMapper();
                        response = invalidRequestExceptionMapper.toResponse(ire);
                    }
                }

                assertEquals(response.getStatus(), expectedStatus, "Unexpected HTTP response status");
                MultivaluedMap<String, Object> responseMetadata = response.getMetadata();

                assertNotNull(responseMetadata, "HTTP response metadata is null");
                // This is the case where a redirect outside happens.
                List<Object> redirectPath = responseMetadata.get(HTTPConstants.HEADER_LOCATION);
                assertTrue(CollectionUtils.isNotEmpty(redirectPath));
                String location = String.valueOf(redirectPath.get(0));
                assertNotNull(location);
                assertTrue(location.contains("subject_token=sample_subject_token"));
                assertFalse(location.contains("error"), "Expected no errors in the redirect url, but found one.");
            }
        }
    }

    @Test(description = "Test redirection with error when request_uri is not sent when " +
            "PAR is mandated in the application")
    public void testErrorWhenPARMandated() throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class)) {
            mockSSOConsentService(false);
            mockOAuthServerConfiguration(oAuthServerConfiguration);
            try (MockedStatic<FrameworkUtils> frameworkUtils = mockStatic(FrameworkUtils.class,
                    Mockito.CALLS_REAL_METHODS);
                 MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
                 MockedStatic<LoggerUtils> loggerUtils = mockStatic(LoggerUtils.class);
                 MockedStatic<CentralLogMgtServiceComponentHolder> centralLogMgtServiceComponentHolder =
                         mockStatic(CentralLogMgtServiceComponentHolder.class);
                 MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class);
                 MockedStatic<OAuth2Util.OAuthURL> oAuthURL = mockStatic(OAuth2Util.OAuthURL.class);
                 MockedStatic<ServiceURLBuilder> serviceURLBuilder = mockStatic(ServiceURLBuilder.class);
                 MockedStatic<EndpointUtil> endpointUtil = mockStatic(EndpointUtil.class, Mockito.CALLS_REAL_METHODS);
                 MockedStatic<OAuth2ServiceFactory> oAuth2ServiceFactory = mockStatic(OAuth2ServiceFactory.class);) {

                oAuth2ServiceFactory.when(OAuth2ServiceFactory::getOAuth2Service).thenReturn(oAuth2Service);
                Map<String, String[]> requestParams = new HashMap<>();
                Map<String, Object> requestAttributes = new HashMap<>();

                requestParams.put(CLIENT_ID, new String[]{CLIENT_ID_VALUE});

                // No consent data is saved in the cache yet and client doesn't send cache key
                requestParams.put(OAuthConstants.SESSION_DATA_KEY_CONSENT, new String[]{null});
                requestParams.put(FrameworkConstants.RequestParams.TO_COMMONAUTH, new String[]{"false"});
                requestParams.put(REDIRECT_URI, new String[]{APP_REDIRECT_URL});
                requestParams.put(OAuth.OAUTH_RESPONSE_TYPE, new String[]{ResponseType.TOKEN.toString()});

                requestAttributes.put(FrameworkConstants.RequestParams.FLOW_STATUS, AuthenticatorFlowStatus.INCOMPLETE);
                // No authentication data is saved in the cache yet and client doesn't send cache key
                requestAttributes.put(FrameworkConstants.SESSION_DATA_KEY, null);

                mockHttpRequest(requestParams, requestAttributes, HttpMethod.POST);

                Map<String, Class<? extends OAuthValidator<HttpServletRequest>>> responseTypeValidators =
                        new Hashtable<>();
                responseTypeValidators.put(ResponseType.CODE.toString(), CodeValidator.class);
                responseTypeValidators.put(ResponseType.TOKEN.toString(), TokenValidator.class);

                when(mockOAuthServerConfiguration.getSupportedResponseTypeValidators()).thenReturn(
                        responseTypeValidators);

                frameworkUtils.when(() -> FrameworkUtils.startTenantFlow(anyString())).thenAnswer(invocation -> null);
                frameworkUtils.when(FrameworkUtils::endTenantFlow).thenAnswer(invocation -> null);
                identityTenantUtil.when(() -> IdentityTenantUtil.getTenantDomain(anyInt()))
                        .thenReturn(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
                identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString()))
                        .thenReturn(MultitenantConstants.SUPER_TENANT_ID);
                loggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(true);
                IdentityEventService eventServiceMock = mock(IdentityEventService.class);

                centralLogMgtServiceComponentHolder.when(CentralLogMgtServiceComponentHolder::getInstance)
                        .thenReturn(centralLogMgtServiceComponentHolderMock);
                when(centralLogMgtServiceComponentHolderMock.getIdentityEventService()).thenReturn(eventServiceMock);
                doNothing().when(eventServiceMock).handleEvent(any());

                mockEndpointUtil(false, endpointUtil);
                when(oAuth2Service.getOauthApplicationState(CLIENT_ID_VALUE)).thenReturn("ACTIVE");
                when(oAuth2Service.isPKCESupportEnabled()).thenReturn(false);

                oAuth2Util.when(() -> OAuth2Util.validatePKCECodeChallenge(anyString(), anyString()))
                        .thenCallRealMethod();
                oAuth2Util.when(() -> OAuth2Util.validatePKCECodeVerifier(anyString())).thenCallRealMethod();
                oAuthURL.when(OAuth2Util.OAuthURL::getOAuth2ErrorPageUrl).thenReturn(ERROR_PAGE_URL);

                OAuthAppDO oAuthAppDO = new OAuthAppDO();
                oAuthAppDO.setRequirePushedAuthorizationRequests(true);
                oAuth2Util.when(() -> OAuth2Util.getAppInformationByClientId(any())).thenReturn(oAuthAppDO);

                OAuth2ClientValidationResponseDTO validationResponseDTO = new OAuth2ClientValidationResponseDTO();
                validationResponseDTO.setValidClient(true);
                validationResponseDTO.setCallbackURL(APP_REDIRECT_URL);
                when(oAuth2Service.validateClientInfo(any())).thenReturn(validationResponseDTO);

                when(oAuth2Service.validateClientInfo(any())).thenReturn(validationResponseDTO);
                oAuth2Util.when(() -> OAuth2Util.getAppInformationByClientId(any(), any())).thenReturn(oAuthAppDO);

                mockServiceURLBuilder(serviceURLBuilder);

                try {
                    oAuth2AuthzEndpoint.authorize(httpServletRequest, httpServletResponse);
                } catch (InvalidRequestParentException ire) {
                    assertTrue(ire instanceof InvalidRequestException);
                    assertEquals(ire.getMessage(), "PAR request is mandatory for the application.");
                }
            }
        }
    }

    @DataProvider(name = "provideUserConsentData")
    public Object[][] provideUserConsentData() {

        String authzCode = "67428657950009705658674645643";
        String accessToken = "56789876734982650746509776325";
        String idToken = "eyJzdWIiOiJQUklNQVJZXC9zdXJlc2hhdHQiLCJlbWFpbCI6InN1cmVzaGdlbXVudUBteW1haWwuY29tIiwibmFtZSI" +
                "6IlN1cmVzaCBBdHRhbmF5YWtlIiwiZmFtaWx5X25hbWUiOiJBdHRhbmF5YWtlIiwicHJlZmVycmVkX3VzZXJuYW1lIjoic3VyZXN" +
                "oZ2VtdW51IiwiZ2l2ZW5fbmFtZSI6IlN1cmVzaCJ9";

        // These values are provided to cover all the branches in handleUserConsent private method.
        return new Object[][]{
                {true, OAuthConstants.Consent.APPROVE_ALWAYS, false, OAuth2ErrorCodes.SERVER_ERROR, null, null, null,
                        null, null, null, null, HttpServletResponse.SC_FOUND, APP_REDIRECT_URL},

                {false, OAuthConstants.Consent.APPROVE_ALWAYS, true, null, authzCode, null, null, null, null, "idp1",
                        null, HttpServletResponse.SC_FOUND, APP_REDIRECT_URL},

                {false, OAuthConstants.Consent.APPROVE_ALWAYS, false, null, null, accessToken, null,
                        OAuthConstants.ACCESS_TOKEN, RESPONSE_MODE_FORM_POST, "idp1", "ACTIVE",
                        HttpServletResponse.SC_OK, null},

                {false, OAuthConstants.Consent.APPROVE_ALWAYS, false, null, null, accessToken, idToken,
                        OAuthConstants.ID_TOKEN, RESPONSE_MODE_FORM_POST, null, "ACTIVE", HttpServletResponse.SC_OK,
                        null},

                {false, OAuthConstants.Consent.APPROVE, false, null, null, accessToken, idToken,
                        OAuthConstants.NONE, RESPONSE_MODE_FORM_POST, "", "", HttpServletResponse.SC_OK, null},

                {false, OAuthConstants.Consent.APPROVE, false, null, null, accessToken, idToken,
                        OAuthConstants.ID_TOKEN, null, null, "ACTIVE", HttpServletResponse.SC_FOUND, APP_REDIRECT_URL},

                {false, OAuthConstants.Consent.APPROVE, false, null, null, accessToken, null, OAuthConstants.ID_TOKEN,
                        null, null, "ACTIVE", HttpServletResponse.SC_FOUND, APP_REDIRECT_URL},

                {false, OAuthConstants.Consent.APPROVE_ALWAYS, false, OAuth2ErrorCodes.INVALID_CLIENT, null, null,
                        null, null, null, null, null, HttpServletResponse.SC_FOUND, APP_REDIRECT_URL},

        };
    }

    @Test(dataProvider = "provideUserConsentData", groups = "testWithConnection")
    public void testHandleUserConsent(boolean isRespDTONull, String consent, boolean skipConsent, String errorCode,
                                      String authCode, String accessToken, String idToken, String responseType,
                                      String responseMode, String authenticatedIdps, String state, int expectedStatus,
                                      String expectedLocation) throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration =
                     mockStatic(OAuthServerConfiguration.class)) {
            mockSSOConsentService(false);
            oAuthServerConfiguration.when(
                    OAuthServerConfiguration::getInstance).thenReturn(mockOAuthServerConfiguration);
            when(mockOAuthServerConfiguration.getAuthorizationCodeValidityPeriodInSeconds()).thenReturn(300L);
            when(mockOAuthServerConfiguration.getOpenIDConnectSkipeUserConsentConfig()).thenReturn(skipConsent);

            try (MockedStatic<SessionDataCache> sessionDataCache = mockStatic(SessionDataCache.class);
                 MockedStatic<OpenIDConnectUserRPStore> openIDConnectUserRPStore =
                         mockStatic(OpenIDConnectUserRPStore.class);
                 MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class);
                 MockedStatic<FrameworkUtils> frameworkUtils = mockStatic(FrameworkUtils.class,
                         Mockito.CALLS_REAL_METHODS);
                 MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
                 MockedStatic<EndpointUtil> endpointUtil = mockStatic(EndpointUtil.class, Mockito.CALLS_REAL_METHODS);
                 MockedStatic<OAuth2ServiceFactory> oAuth2ServiceFactory = mockStatic(OAuth2ServiceFactory.class)) {
                Map<String, String[]> requestParams = new HashMap<>();
                Map<String, Object> requestAttributes = new HashMap<>();

                requestParams.put(OAuthConstants.SESSION_DATA_KEY_CONSENT,
                        new String[]{SESSION_DATA_KEY_CONSENT_VALUE});
                requestParams.put(FrameworkConstants.RequestParams.TO_COMMONAUTH, new String[]{"false"});
                requestParams.put(OAuthConstants.OAuth20Params.SCOPE, new String[]{OAuthConstants.Scope.OPENID});
                requestParams.put(OAuthConstants.Prompt.CONSENT, new String[]{consent});
                requestParams.put(CLIENT_ID, new String[]{CLIENT_ID_VALUE});

                requestAttributes.put(FrameworkConstants.RequestParams.FLOW_STATUS, AuthenticatorFlowStatus.INCOMPLETE);

                mockHttpRequest(requestParams, requestAttributes, HttpMethod.POST);

                sessionDataCache.when(SessionDataCache::getInstance).thenReturn(mockSessionDataCache);
                SessionDataCacheKey consentDataCacheKey = new SessionDataCacheKey(SESSION_DATA_KEY_CONSENT_VALUE);
                when(mockSessionDataCache.getValueFromCache(consentDataCacheKey)).thenReturn(consentCacheEntry);

                OAuth2Parameters oAuth2Params =
                        setOAuth2Parameters(new HashSet<>(), APP_NAME, responseMode, APP_REDIRECT_URL, null);
                oAuth2Params.setResponseType(responseType);
                oAuth2Params.setState(state);
                oAuth2Params.setClientId(CLIENT_ID_VALUE);

                when(consentCacheEntry.getoAuth2Parameters()).thenReturn(oAuth2Params);
                when(consentCacheEntry.getLoggedInUser()).thenReturn(new AuthenticatedUser());
                when(consentCacheEntry.getAuthenticatedIdPs()).thenReturn(authenticatedIdps);

                OAuth2AuthorizeRespDTO authzRespDTO = null;
                if (!isRespDTONull) {
                    authzRespDTO = new OAuth2AuthorizeRespDTO();
                    authzRespDTO.setAuthorizationCode(authCode);
                    authzRespDTO.setCallbackURI(APP_REDIRECT_URL);
                    authzRespDTO.setAccessToken(accessToken);
                    authzRespDTO.setIdToken(idToken);
                    authzRespDTO.setErrorCode(errorCode);

                    if (OAuthConstants.ID_TOKEN.equals(responseType) && idToken == null) {
                        authzRespDTO.setCallbackURI(APP_REDIRECT_URL + "?");
                    }
                }
                mockEndpointUtil(false, endpointUtil);
                oAuth2ServiceFactory.when(OAuth2ServiceFactory::getOAuth2Service).thenReturn(oAuth2Service);
                when(oAuth2Service.authorize(any(OAuthAuthzReqMessageContext.class))).thenReturn(authzRespDTO);
                when(oAuth2Service.getOauthApplicationState(CLIENT_ID_VALUE)).thenReturn("ACTIVE");

                openIDConnectUserRPStore.when(
                        OpenIDConnectUserRPStore::getInstance).thenReturn(mockOpenIDConnectUserRPStore);
                doNothing().when(mockOpenIDConnectUserRPStore).putUserRPToStore(any(AuthenticatedUser.class),
                        anyString(), anyBoolean(), anyString());

                oAuth2Util.when(() -> OAuth2Util.getServiceProvider(CLIENT_ID_VALUE)).thenReturn(new ServiceProvider());
                mockApplicationManagementService();
                frameworkUtils.when(() -> FrameworkUtils.startTenantFlow(anyString())).thenAnswer(invocation -> null);
                frameworkUtils.when(FrameworkUtils::endTenantFlow).thenAnswer(invocation -> null);
                identityTenantUtil.when(() -> IdentityTenantUtil.getTenantDomain(anyInt())).thenReturn(
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
                identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString()))
                        .thenReturn(MultitenantConstants.SUPER_TENANT_ID);

                OAuth2AuthorizeReqDTO authorizeReqDTO = new OAuth2AuthorizeReqDTO();
                OAuthAuthzReqMessageContext authzReqMsgCtx = new OAuthAuthzReqMessageContext(authorizeReqDTO);
                when(consentCacheEntry.getAuthzReqMsgCtx()).thenReturn(authzReqMsgCtx);

                OAuth2ServiceComponentHolder.getInstance()
                        .setAuthorizationDetailsService(authorizationDetailsServiceMock);

                Response response;
                try {
                    setSupportedResponseModes();
                    response = oAuth2AuthzEndpoint.authorize(httpServletRequest, httpServletResponse);
                } catch (InvalidRequestParentException ire) {
                    InvalidRequestExceptionMapper invalidRequestExceptionMapper = new InvalidRequestExceptionMapper();
                    response = invalidRequestExceptionMapper.toResponse(ire);
                }

                assertNotNull(response, "Authorization response is null");
                assertEquals(response.getStatus(), expectedStatus, "Unexpected HTTP response status");

                if (expectedLocation != null) {
                    MultivaluedMap<String, Object> responseMetadata = response.getMetadata();
                    assertNotNull(responseMetadata, "Response metadata is null");

                    assertTrue(CollectionUtils.isNotEmpty(responseMetadata.get(HTTPConstants.HEADER_LOCATION)),
                            "Location header not found in the response");
                    String location = String.valueOf(responseMetadata.get(HTTPConstants.HEADER_LOCATION).get(0));
                    assertTrue(location.contains(expectedLocation), "Unexpected redirect url in the response");

                    if (errorCode != null) {
                        assertTrue(location.contains(errorCode), "Expected error code not found in URL");
                    }
                }
            }
        }
    }

    @DataProvider(name = "provideDataForUserAuthz")
    public Object[][] provideDataForUserAuthz() {

        String idTokenHint = "tokenHintString";

        // This object provides data to cover all branches in doUserAuthz() private method
        return new Object[][]{
                {OAuthConstants.Prompt.CONSENT, null, true, false, false, USERNAME, USERNAME, null},
                {OAuthConstants.Prompt.NONE, null, true, true, false, USERNAME, USERNAME, null},
                {OAuthConstants.Prompt.NONE, null, false, false, false, USERNAME, USERNAME,
                        OAuth2ErrorCodes.CONSENT_REQUIRED},
                {OAuthConstants.Prompt.NONE, null, false, true, false, USERNAME, USERNAME, null},
                {OAuthConstants.Prompt.NONE, idTokenHint, true, false, true, USERNAME, USERNAME, null},
                {OAuthConstants.Prompt.NONE, idTokenHint, true, false, false, USERNAME, USERNAME, null},
                {OAuthConstants.Prompt.NONE, idTokenHint, false, false, true, USERNAME, USERNAME,
                        OAuth2ErrorCodes.CONSENT_REQUIRED},
                {OAuthConstants.Prompt.NONE, "invalid", false, false, true, USERNAME, USERNAME, null},
                {OAuthConstants.Prompt.NONE, idTokenHint, false, false, true, "", USERNAME,
                        OAuth2ErrorCodes.LOGIN_REQUIRED},
                {OAuthConstants.Prompt.NONE, idTokenHint, true, false, true, USERNAME, "user2",
                        OAuth2ErrorCodes.LOGIN_REQUIRED},
                {OAuthConstants.Prompt.LOGIN, null, true, false, false, USERNAME, USERNAME, null},
                {OAuthConstants.Prompt.LOGIN, null, false, false, false, USERNAME, USERNAME, null},
                {"", null, false, true, false, USERNAME, USERNAME, null},
                {OAuthConstants.Prompt.SELECT_ACCOUNT, null, false, false, false, USERNAME, USERNAME, null},
        };
    }

    @Test(dataProvider = "provideDataForUserAuthz", groups = "testWithConnection")
    public void testDoUserAuthz(String prompt, String idTokenHint, boolean hasUserApproved, boolean skipConsent,
                                boolean idTokenHintValid, String loggedInUser, String idTokenHintSubject,
                                String errorCode) throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration =
                     mockStatic(OAuthServerConfiguration.class);
             MockedStatic<SSOConsentServiceFactory> ssoConsentServiceFactory =
                     mockStatic(SSOConsentServiceFactory.class)) {
            ssoConsentServiceFactory.when(SSOConsentServiceFactory::getSSOConsentService)
                    .thenReturn(mockedSSOConsentService);
            mockSSOConsentService(false);
            mockOAuthServerConfiguration(oAuthServerConfiguration);
            try (MockedStatic<SessionDataCache> sessionDataCache = mockStatic(SessionDataCache.class);
                 MockedStatic<OpenIDConnectUserRPStore> openIDConnectUserRPStore =
                         mockStatic(OpenIDConnectUserRPStore.class);
                 MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class, Mockito.CALLS_REAL_METHODS);
                 MockedStatic<SignedJWT> signedJWT = mockStatic(SignedJWT.class);
                 MockedStatic<AuthorizationHandlerManager> authorizationHandlerManager =
                         mockStatic(AuthorizationHandlerManager.class);
                 MockedStatic<FrameworkUtils> frameworkUtils = mockStatic(FrameworkUtils.class,
                         Mockito.CALLS_REAL_METHODS);
                 MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class,
                         Mockito.CALLS_REAL_METHODS);
                 MockedStatic<EndpointUtil> endpointUtil = mockStatic(EndpointUtil.class, Mockito.CALLS_REAL_METHODS);
                 MockedStatic<OAuth2ServiceFactory> oAuth2ServiceFactory = mockStatic(OAuth2ServiceFactory.class)) {

                oAuth2ServiceFactory.when(OAuth2ServiceFactory::getOAuth2Service).thenReturn(oAuth2Service);
                AuthenticationResult result = setAuthenticationResult(true, null, null,
                        null, null);

                result.getSubject().setAuthenticatedSubjectIdentifier(loggedInUser);
                Map<String, String[]> requestParams = new HashMap<>();
                Map<String, Object> requestAttributes = new HashMap<>();

                requestParams.put(CLIENT_ID, new String[]{CLIENT_ID_VALUE});
                requestParams.put(FrameworkConstants.RequestParams.TO_COMMONAUTH, new String[]{"false"});
                requestParams.put(OAuthConstants.OAuth20Params.SCOPE, new String[]{OAuthConstants.Scope.OPENID});

                requestAttributes.put(FrameworkConstants.RequestParams.FLOW_STATUS, AuthenticatorFlowStatus.INCOMPLETE);
                requestAttributes.put(FrameworkConstants.SESSION_DATA_KEY, SESSION_DATA_KEY_VALUE);
                requestAttributes.put(FrameworkConstants.RequestAttribute.AUTH_RESULT, result);

                mockHttpRequest(requestParams, requestAttributes, HttpMethod.POST);

                OAuth2Parameters oAuth2Params =
                        setOAuth2Parameters(new HashSet<>(), APP_NAME, null, APP_REDIRECT_URL, null);
                oAuth2Params.setClientId(CLIENT_ID_VALUE);
                oAuth2Params.setPrompt(prompt);
                oAuth2Params.setIDTokenHint(idTokenHint);

                sessionDataCache.when(SessionDataCache::getInstance).thenReturn(mockSessionDataCache);
                SessionDataCacheKey loginDataCacheKey = new SessionDataCacheKey(SESSION_DATA_KEY_VALUE);
                when(mockSessionDataCache.getValueFromCache(loginDataCacheKey)).thenReturn(loginCacheEntry);
                when(loginCacheEntry.getLoggedInUser()).thenReturn(result.getSubject());
                when(loginCacheEntry.getoAuth2Parameters()).thenReturn(oAuth2Params);

                mockEndpointUtil(false, endpointUtil);
                when(oAuth2ScopeService.hasUserProvidedConsentForAllRequestedScopes(
                        anyString(), anyString(), anyInt(), anyList())).thenReturn(hasUserApproved);

                openIDConnectUserRPStore.when(OpenIDConnectUserRPStore::getInstance)
                        .thenReturn(mockOpenIDConnectUserRPStore);
                when(mockOpenIDConnectUserRPStore.hasUserApproved(any(AuthenticatedUser.class), anyString(),
                        anyString())).
                        thenReturn(hasUserApproved);

                oAuth2Util.when(() -> OAuth2Util.validateIdToken(anyString())).thenReturn(idTokenHintValid);

                if ("invalid".equals(idTokenHint)) {
                    signedJWT.when(() -> SignedJWT.parse(anyString())).thenThrow(new ParseException("error", 1));
                } else {
                    signedJWT.when(() -> SignedJWT.parse(anyString())).thenReturn(mockSignedJWT);
                }
                JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
                jwtClaimsSetBuilder.subject(idTokenHintSubject);
                JWTClaimsSet jwtClaimsSet = jwtClaimsSetBuilder.build();
                when(mockSignedJWT.getJWTClaimsSet()).thenReturn(jwtClaimsSet);
                when(oAuth2Service.getOauthApplicationState(CLIENT_ID_VALUE)).thenReturn("ACTIVE");

                mockApplicationManagementService();

                authorizationHandlerManager.when(
                        AuthorizationHandlerManager::getInstance).thenReturn(mockAuthorizationHandlerManager);

                OAuth2AuthorizeReqDTO authzReqDTO = new OAuth2AuthorizeReqDTO();
                authzReqDTO.setConsumerKey(CLIENT_ID_VALUE);
                authzReqDTO.setScopes(new String[]{OAuthConstants.Scope.OPENID});
                authzReqDTO.setUser(loginCacheEntry.getLoggedInUser());
                authzReqDTO.setResponseType("code");
                OAuthAuthzReqMessageContext authzReqMsgCtx = new OAuthAuthzReqMessageContext(authzReqDTO);
                authzReqMsgCtx.setApprovedScope(new String[]{OAuthConstants.Scope.OPENID});
                when(oAuth2Service.validateScopesBeforeConsent(any(OAuth2AuthorizeReqDTO.class))).thenReturn(
                        authzReqMsgCtx);
                when(mockAuthorizationHandlerManager.validateScopesBeforeConsent(any(OAuth2AuthorizeReqDTO.class)))
                        .thenReturn(authzReqMsgCtx);
                when(loginCacheEntry.getAuthzReqMsgCtx()).thenReturn(authzReqMsgCtx);

                frameworkUtils.when(() -> FrameworkUtils.resolveUserIdFromUsername(anyInt(), anyString(), anyString()))
                        .thenReturn("sample");
                frameworkUtils.when(() -> FrameworkUtils.startTenantFlow(anyString())).thenAnswer(
                        invocation -> null);
                frameworkUtils.when(FrameworkUtils::endTenantFlow).thenAnswer(invocation -> null);

                identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(nullable(String.class)))
                        .thenReturn(MultitenantConstants.SUPER_TENANT_ID);
                identityTenantUtil.when(() -> IdentityTenantUtil.getTenantDomain(anyInt()))
                        .thenReturn(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);

                Response response;
                try {
                    setSupportedResponseModes();
                    response = oAuth2AuthzEndpoint.authorize(httpServletRequest, httpServletResponse);
                } catch (InvalidRequestParentException ire) {
                    InvalidRequestExceptionMapper invalidRequestExceptionMapper = new InvalidRequestExceptionMapper();
                    response = invalidRequestExceptionMapper.toResponse(ire);
                }

                assertNotNull(response, "Authorization response is null");
                assertEquals(response.getStatus(), HttpServletResponse.SC_FOUND, "Unexpected HTTP response status");

                MultivaluedMap<String, Object> responseMetadata = response.getMetadata();
                assertNotNull(responseMetadata, "Response metadata is null");

                assertTrue(CollectionUtils.isNotEmpty(responseMetadata.get(HTTPConstants.HEADER_LOCATION)),
                        "Location header not found in the response");
                String location = String.valueOf(responseMetadata.get(HTTPConstants.HEADER_LOCATION).get(0));
                assertFalse(location.isEmpty(), "Redirect URL is empty");
                log.info("Redirect URL: " + location);
                if (errorCode != null) {
                    assertTrue(location.contains(errorCode), "Expected error code not found in URL");
                }
            }
        }
    }

    @DataProvider(name = "provideOidcSessionData")
    public Object[][] provideOidcSessionData() {

        Cookie opBrowserStateCookie = new Cookie("opbs", "2345678776gffdgdsfafa");
        OIDCSessionState previousSessionState1 = new OIDCSessionState();
        OIDCSessionState previousSessionState2 = new OIDCSessionState();

        previousSessionState1.setSessionParticipants(new HashSet<>(Arrays.asList(CLIENT_ID_VALUE)));
        previousSessionState2.setSessionParticipants(new HashSet<String>());

        String[] returnValues = new String[]{
                "http://localhost:8080/redirect?session_state=sessionStateValue",
                "<form method=\"post\" action=\"http://localhost:8080/redirect\">"
        };

        // This object provides values to cover the branches in ManageOIDCSessionState() private method
        return new Object[][]{
                {opBrowserStateCookie, previousSessionState1, APP_REDIRECT_URL, null,
                        HttpServletResponse.SC_FOUND, returnValues[0]},
                {opBrowserStateCookie, previousSessionState2, APP_REDIRECT_URL, RESPONSE_MODE_FORM_POST,
                        HttpServletResponse.SC_OK, returnValues[1]},
                {null, previousSessionState1, APP_REDIRECT_URL, null, HttpServletResponse.SC_FOUND, returnValues[0]},
                {null, previousSessionState1, APP_REDIRECT_URL, null, HttpServletResponse.SC_FOUND, returnValues[0]},
                {opBrowserStateCookie, null, APP_REDIRECT_URL, null, HttpServletResponse.SC_FOUND, returnValues[0]},
                {opBrowserStateCookie, previousSessionState1, APP_REDIRECT_URL, RESPONSE_MODE_FORM_POST,
                        HttpServletResponse.SC_OK, returnValues[1]},
        };
    }

    @Test(dataProvider = "provideOidcSessionData", groups = "testWithConnection")
    public void testManageOIDCSessionState(Object cookieObject, Object sessionStateObject, String callbackUrl,
                                           String responseMode, int expectedStatus, String expectedResult)
            throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class)) {
            mockSSOConsentService(false);
            mockOAuthServerConfiguration(oAuthServerConfiguration);
            try (MockedStatic<OAuth2Util.OAuthURL> oAuthURL = mockStatic(OAuth2Util.OAuthURL.class);
                 MockedStatic<OIDCSessionManagementUtil> oidcSessionManagementUtil =
                         mockStatic(OIDCSessionManagementUtil.class);
                 MockedStatic<SessionDataCache> sessionDataCache = mockStatic(SessionDataCache.class);
                 MockedStatic<OpenIDConnectUserRPStore> openIDConnectUserRPStore =
                         mockStatic(OpenIDConnectUserRPStore.class);
                 MockedStatic<AuthorizationHandlerManager> authorizationHandlerManager =
                         mockStatic(AuthorizationHandlerManager.class);
                 MockedStatic<FrameworkUtils> frameworkUtils = mockStatic(FrameworkUtils.class,
                         Mockito.CALLS_REAL_METHODS);
                 MockedStatic<IdentityTenantUtil> identityTenantUtil =
                         mockStatic(IdentityTenantUtil.class, Mockito.CALLS_REAL_METHODS);
                 MockedStatic<EndpointUtil> endpointUtil = mockStatic(EndpointUtil.class, Mockito.CALLS_REAL_METHODS);
                 MockedStatic<OAuthServerConfigurationFactory> oAuthServerConfigurationFactory =
                         mockStatic(OAuthServerConfigurationFactory.class);
                 MockedStatic<OAuth2ServiceFactory> oAuth2ServiceFactory = mockStatic(OAuth2ServiceFactory.class)) {

                oAuth2ServiceFactory.when(OAuth2ServiceFactory::getOAuth2Service).thenReturn(oAuth2Service);
                Cookie opBrowserStateCookie = (Cookie) cookieObject;
                Cookie newOpBrowserStateCookie = new Cookie("opbs", "f6454r678776gffdgdsfafa");
                OIDCSessionState previousSessionState = (OIDCSessionState) sessionStateObject;
                AuthenticationResult result = setAuthenticationResult(true, null, null,
                        null, null);

                Map<String, String[]> requestParams = new HashMap<>();
                Map<String, Object> requestAttributes = new HashMap<>();

                requestParams.put(CLIENT_ID, new String[]{CLIENT_ID_VALUE});
                requestParams.put(FrameworkConstants.RequestParams.TO_COMMONAUTH, new String[]{"false"});
                requestParams.put(OAuthConstants.OAuth20Params.SCOPE, new String[]{OAuthConstants.Scope.OPENID});
                requestParams.put(OAuthConstants.OAuth20Params.PROMPT, new String[]{OAuthConstants.Prompt.LOGIN});

                requestAttributes.put(FrameworkConstants.RequestParams.FLOW_STATUS, AuthenticatorFlowStatus.INCOMPLETE);
                requestAttributes.put(FrameworkConstants.SESSION_DATA_KEY, SESSION_DATA_KEY_VALUE);
                requestAttributes.put(FrameworkConstants.RequestAttribute.AUTH_RESULT, result);

                mockHttpRequest(requestParams, requestAttributes, HttpMethod.POST);

                OAuth2Parameters oAuth2Params =
                        setOAuth2Parameters(new HashSet<>(Arrays.asList(OAuthConstants.Scope.OPENID)),
                                APP_NAME, responseMode, APP_REDIRECT_URL, null);
                oAuth2Params.setClientId(CLIENT_ID_VALUE);
                oAuth2Params.setPrompt(OAuthConstants.Prompt.LOGIN);

                mockEndpointUtil(false, endpointUtil);
                oAuthServerConfigurationFactory.when(OAuthServerConfigurationFactory::getOAuthServerConfiguration)
                                .thenReturn(mockOAuthServerConfiguration);
                when(mockOAuthServerConfiguration.getOpenIDConnectSkipeUserConsentConfig()).thenReturn(true);

                OAuth2AuthorizeRespDTO authzRespDTO = new OAuth2AuthorizeRespDTO();
                authzRespDTO.setCallbackURI(callbackUrl);
                when(oAuth2Service.authorize(any(OAuthAuthzReqMessageContext.class))).thenReturn(authzRespDTO);

                oAuthURL.when(OAuth2Util.OAuthURL::getOAuth2ErrorPageUrl).thenReturn(ERROR_PAGE_URL);

                oidcSessionManagementUtil.when(
                                () -> OIDCSessionManagementUtil.getOPBrowserStateCookie(any(HttpServletRequest.class)))
                        .thenReturn(opBrowserStateCookie);
                oidcSessionManagementUtil.when(
                                () -> OIDCSessionManagementUtil.addOPBrowserStateCookie(any(HttpServletResponse.class)))
                        .thenReturn(newOpBrowserStateCookie);
                oidcSessionManagementUtil.when(
                                () -> OIDCSessionManagementUtil.addOPBrowserStateCookie(any(HttpServletResponse.class),
                                        any(HttpServletRequest.class), nullable(String.class), nullable(String.class)))
                        .thenReturn(newOpBrowserStateCookie);
                oidcSessionManagementUtil.when(OIDCSessionManagementUtil::getSessionManager)
                        .thenReturn(oidcSessionManager);
                when(oidcSessionManager.getOIDCSessionState(anyString(), any(String.class))).thenReturn(
                        previousSessionState);
                oidcSessionManagementUtil.when(
                                () -> OIDCSessionManagementUtil.getSessionStateParam(anyString(), anyString()
                                        , anyString()))
                        .thenReturn("sessionStateValue");
                oidcSessionManagementUtil.when(
                        () -> OIDCSessionManagementUtil.addSessionStateToURL(anyString(), anyString(),
                                isNull())).thenCallRealMethod();

                sessionDataCache.when(SessionDataCache::getInstance).thenReturn(mockSessionDataCache);
                SessionDataCacheKey loginDataCacheKey = new SessionDataCacheKey(SESSION_DATA_KEY_VALUE);
                when(mockSessionDataCache.getValueFromCache(loginDataCacheKey)).thenReturn(loginCacheEntry);
                when(loginCacheEntry.getoAuth2Parameters()).thenReturn(oAuth2Params);
                when(loginCacheEntry.getLoggedInUser()).thenReturn(result.getSubject());

                openIDConnectUserRPStore.when(OpenIDConnectUserRPStore::getInstance)
                        .thenReturn(mockOpenIDConnectUserRPStore);
                when(mockOpenIDConnectUserRPStore.hasUserApproved(any(AuthenticatedUser.class), anyString(),
                        anyString())).
                        thenReturn(true);
                when(oAuth2Service.getOauthApplicationState(CLIENT_ID_VALUE)).thenReturn("ACTIVE");

                mockApplicationManagementService();

                authorizationHandlerManager.when(
                        AuthorizationHandlerManager::getInstance).thenReturn(mockAuthorizationHandlerManager);

                OAuth2AuthorizeReqDTO authzReqDTO = new OAuth2AuthorizeReqDTO();
                authzReqDTO.setConsumerKey(CLIENT_ID_VALUE);
                authzReqDTO.setScopes(new String[]{OAuthConstants.Scope.OPENID});
                authzReqDTO.setCallbackUrl(callbackUrl);
                authzReqDTO.setUser(loginCacheEntry.getLoggedInUser());
                authzReqDTO.setResponseType("code");
                OAuthAuthzReqMessageContext authzReqMsgCtx = new OAuthAuthzReqMessageContext(authzReqDTO);
                authzReqMsgCtx.setApprovedScope(new String[]{OAuthConstants.Scope.OPENID});
                when(oAuth2Service.validateScopesBeforeConsent(any(OAuth2AuthorizeReqDTO.class))).thenReturn(
                        authzReqMsgCtx);
                when(mockAuthorizationHandlerManager.validateScopesBeforeConsent(any(OAuth2AuthorizeReqDTO.class)))
                        .thenReturn(authzReqMsgCtx);
                when(loginCacheEntry.getAuthzReqMsgCtx()).thenReturn(authzReqMsgCtx);
                frameworkUtils.when(() -> FrameworkUtils.resolveUserIdFromUsername(anyInt(), anyString(), anyString()))
                        .thenReturn("sample");
                frameworkUtils.when(() -> FrameworkUtils.startTenantFlow(anyString())).thenAnswer(invocation -> null);
                frameworkUtils.when(FrameworkUtils::endTenantFlow).thenAnswer(invocation -> null);

                identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(nullable(String.class)))
                        .thenReturn(MultitenantConstants.SUPER_TENANT_ID);
                identityTenantUtil.when(() -> IdentityTenantUtil.getTenantDomain(anyInt()))
                        .thenReturn(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);

                Response response;
                try {
                    setSupportedResponseModes();
                    response = oAuth2AuthzEndpoint.authorize(httpServletRequest, httpServletResponse);
                } catch (InvalidRequestParentException ire) {
                    InvalidRequestExceptionMapper invalidRequestExceptionMapper = new InvalidRequestExceptionMapper();
                    response = invalidRequestExceptionMapper.toResponse(ire);
                }

                assertNotNull(response, "Authorization response is null");
                assertEquals(response.getStatus(), expectedStatus, "Unexpected HTTP response status");

                MultivaluedMap<String, Object> responseMetadata = response.getMetadata();
                assertNotNull(responseMetadata, "Response metadata is null");

                if (response.getStatus() != HttpServletResponse.SC_OK) {
                    assertTrue(CollectionUtils.isNotEmpty(responseMetadata.get(HTTPConstants.HEADER_LOCATION)),
                            "Location header not found in the response");
                    String location = String.valueOf(responseMetadata.get(HTTPConstants.HEADER_LOCATION).get(0));

                    assertTrue(location.contains(expectedResult), "Expected redirect URL is not returned");
                } else {
                    assertTrue(response.getEntity().toString().contains(expectedResult),
                            "Expected redirect URL is not returned");
                }
            }
        }
    }

    private void mockApplicationManagementService() throws IdentityApplicationManagementException {

        mockApplicationManagementService(new ServiceProvider());
    }

    private void mockApplicationManagementService(ServiceProvider sp) throws IdentityApplicationManagementException {

        ApplicationManagementService appMgtService = mock(ApplicationManagementService.class);
        when(appMgtService.getServiceProviderByClientId(anyString(), anyString(), anyString())).thenReturn(sp);
        OAuth2ServiceComponentHolder.setApplicationMgtService(appMgtService);
    }

    @DataProvider(name = "provideSessionContextData")
    public Object[][] provideSessionContextData() {

        return new Object[][]{{"1234", "1234"}, {null, null}, {"1234", ""}};
    }

    @DataProvider(name = "providePathExistsData")
    public Object[][] providePathExistsData() {

        return new Object[][]{
                {System.getProperty(CarbonBaseConstants.CARBON_HOME), true},
                {"carbon_home", false}
        };
    }

    @Test(dataProvider = "providePathExistsData")
    public void testGetFormPostRedirectPage(String carbonHome, boolean fileExists) throws Exception {

        try (MockedStatic<CarbonUtils> carbonUtils = mockStatic(CarbonUtils.class, Mockito.CALLS_REAL_METHODS);) {
            carbonUtils.when(CarbonUtils::getCarbonHome).thenReturn(carbonHome);
            Method getFormPostRedirectPage =
                    authzEndpointObject.getClass().getDeclaredMethod("getFormPostRedirectPage");
            getFormPostRedirectPage.setAccessible(true);
            String value = (String) getFormPostRedirectPage.invoke(authzEndpointObject);
            assertEquals((value != null), fileExists, "FormPostRedirectPage value is incorrect");

            Field formPostRedirectPage = authzEndpointObject.getClass().getDeclaredField("formPostRedirectPage");
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
            modifiers.setInt(formPostRedirectPage, formPostRedirectPage.getModifiers() & ~Modifier.FINAL);

            formPostRedirectPage.setAccessible(true);
            formPostRedirectPage.set(authzEndpointObject, value);

            Method createFormPage = authzEndpointObject.getClass().getDeclaredMethod("createFormPage", String.class,
                    String.class, String.class, String.class);
            createFormPage.setAccessible(true);
            value = (String) createFormPage.invoke(authzEndpointObject, APP_REDIRECT_URL_JSON, APP_REDIRECT_URL,
                    StringUtils.EMPTY, "sessionDataValue");
            assertNotNull(value, "Form post page is null");

            Method createErrorFormPage = authzEndpointObject.getClass().getDeclaredMethod("createErrorFormPage",
                    String.class, OAuthProblemException.class);
            createErrorFormPage.setAccessible(true);
            value = (String) createErrorFormPage.invoke(authzEndpointObject, APP_REDIRECT_URL, oAuthProblemException);
            assertNotNull(value, "Form post error page is null");
        }
    }

    @DataProvider(name = "provideSendRequestToFrameworkData")
    public Object[][] provideSendRequestToFrameworkData() {

        return addDiagnosticLogStatusToExistingDataProvider(new Object[][]{
                {null},
                {AuthenticatorFlowStatus.SUCCESS_COMPLETED},
                {AuthenticatorFlowStatus.INCOMPLETE}
        });
    }

    @Test(dataProvider = "provideSendRequestToFrameworkData")
    public void testSendRequestToFramework(Object flowStatusObject, boolean diagnosticLogsEnabled) throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);) {
            mockOAuthServerConfiguration(oAuthServerConfiguration);
            try (MockedStatic<LoggerUtils> loggerUtils = mockStatic(LoggerUtils.class);
                 MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
                 MockedStatic<FrameworkUtils> frameworkUtils = mockStatic(FrameworkUtils.class,
                         Mockito.CALLS_REAL_METHODS);
                 MockedStatic<OAuth2Util.OAuthURL> oAuthURL = mockStatic(OAuth2Util.OAuthURL.class);) {

                AuthenticatorFlowStatus flowStatus = (AuthenticatorFlowStatus) flowStatusObject;
                Map<String, String[]> requestParams = new HashMap<>();
                Map<String, Object> requestAttributes = new HashMap<>();

                requestAttributes.put(FrameworkConstants.RequestParams.FLOW_STATUS, flowStatus);
                mockHttpRequest(requestParams, requestAttributes, HttpMethod.POST);

                loggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(diagnosticLogsEnabled);
                identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString()))
                        .thenReturn(MultitenantConstants.SUPER_TENANT_ID);

                final String[] redirectUrl = new String[1];
                doAnswer((Answer<Object>) invocation -> {

                    String key = (String) invocation.getArguments()[0];
                    redirectUrl[0] = key;
                    return null;
                }).when(httpServletResponse).sendRedirect(anyString());

                frameworkUtils.when(FrameworkUtils::getRequestCoordinator).thenReturn(requestCoordinator);
                frameworkUtils.when(() -> FrameworkUtils.startTenantFlow(anyString())).thenAnswer(invocation -> null);
                frameworkUtils.when(FrameworkUtils::endTenantFlow).thenAnswer(invocation -> null);

                doAnswer(
                        (Answer<Object>) invocation -> null).when(requestCoordinator)
                        .handle(any(HttpServletRequest.class), any(HttpServletResponse.class));

                oAuthURL.when(OAuth2Util.OAuthURL::getOAuth2ErrorPageUrl).thenReturn(ERROR_PAGE_URL);

                Method sendRequestToFramework =
                        authzEndpointObject.getClass().getDeclaredMethod("handleAuthFlowThroughFramework",
                                OAuthMessage.class, String.class, String.class);
                sendRequestToFramework.setAccessible(true);

                when(oAuthMessage.getRequest()).thenReturn(httpServletRequest);
                when(oAuthMessage.getResponse()).thenReturn(httpServletResponse);

                Response response;
                try {
                    response = (Response) sendRequestToFramework.invoke(authzEndpointObject, oAuthMessage, "type");
                } catch (Exception ire) {
                    InvalidRequestExceptionMapper invalidRequestExceptionMapper = new InvalidRequestExceptionMapper();
                    response = invalidRequestExceptionMapper.toResponse((InvalidRequestParentException) ire.getCause());
                }

                assertNotNull(response, "Returned response is null");

                requestAttributes.put(FrameworkConstants.RequestParams.FLOW_STATUS, flowStatus);
                mockHttpRequest(requestParams, requestAttributes, HttpMethod.POST);

                when(oAuthMessage.getRequest()).thenReturn(httpServletRequest);
                when(oAuthMessage.getResponse()).thenReturn(httpServletResponse);

                Method sendRequestToFramework2 =
                        authzEndpointObject.getClass().getDeclaredMethod("handleAuthFlowThroughFramework",
                                OAuthMessage.class, String.class, String.class);
                sendRequestToFramework2.setAccessible(true);
                try {
                    response = (Response) sendRequestToFramework.invoke(authzEndpointObject, oAuthMessage, "type");
                } catch (Exception ire) {
                    InvalidRequestExceptionMapper invalidRequestExceptionMapper = new InvalidRequestExceptionMapper();
                    response = invalidRequestExceptionMapper.toResponse((InvalidRequestParentException) ire.getCause());
                }
                assertNotNull(response, "Returned response is null");
            }
        }
    }

    @DataProvider(name = "provideAuthenticatedTimeFromCommonAuthData")
    public Object[][] provideAuthenticatedTimeFromCommonAuthData() {

        return new Object[][]{
                {new SessionContext(), 1479249799770L, 1479249798770L},
                {new SessionContext(), null, 1479249798770L},
                {null, null, 1479249798770L}
        };
    }

    @Test(dataProvider = "provideAuthenticatedTimeFromCommonAuthData")
    public void testGetAuthenticatedTimeFromCommonAuthCookieValue(Object sessionContextObject, Object updatedTimestamp,
                                                                  Object createdTimeStamp) throws Exception {

        try (MockedStatic<FrameworkUtils> frameworkUtils = mockStatic(FrameworkUtils.class);) {

            SessionContext sessionContext = (SessionContext) sessionContextObject;
            Cookie commonAuthCookie = new Cookie(FrameworkConstants.COMMONAUTH_COOKIE, "32414141346576");

            if (sessionContext != null) {
                sessionContext.addProperty(FrameworkConstants.UPDATED_TIMESTAMP, updatedTimestamp);
                sessionContext.addProperty(FrameworkConstants.CREATED_TIMESTAMP, createdTimeStamp);
            }

            frameworkUtils.when(() -> FrameworkUtils.getSessionContextFromCache(anyString(), anyString()))
                    .thenReturn(sessionContext);

            Method getAuthenticatedTimeFromCommonAuthCookieValue = authzEndpointObject.getClass().
                    getDeclaredMethod("getAuthenticatedTimeFromCommonAuthCookieValue", String.class, String.class);
            getAuthenticatedTimeFromCommonAuthCookieValue.setAccessible(true);
            long timestamp = (long) getAuthenticatedTimeFromCommonAuthCookieValue.invoke(authzEndpointObject,
                    commonAuthCookie.getValue(), "abc");

            if (sessionContext == null) {
                assertEquals(timestamp, 0, "Authenticated time should be 0 when session context is null");
            } else if (updatedTimestamp != null) {
                assertEquals(timestamp, Long.parseLong(updatedTimestamp.toString()),
                        "session context updated time should be equal to the authenticated time");
            } else {
                assertEquals(timestamp, Long.parseLong(createdTimeStamp.toString()),
                        "session context created time should be equal to the authenticated time");
            }
        }
    }

    @DataProvider(name = "provideGetServiceProviderData")
    public Object[][] provideGetServiceProviderData() {

        return new Object[][]{
                {CLIENT_ID_VALUE, null},
                {CLIENT_ID_VALUE, new IdentityApplicationManagementException("Error")},
                {CLIENT_ID_VALUE, new IdentityOAuth2ClientException("Error")},
                {"invalidId", null},
        };
    }

    @Test(dataProvider = "provideGetServiceProviderData", groups = "testWithConnection")
    public void testGetServiceProvider(String clientId, Exception e) throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);) {
            mockOAuthServerConfiguration(oAuthServerConfiguration);
            try (MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
                 MockedStatic<EndpointUtil> endpointUtil = mockStatic(EndpointUtil.class, Mockito.CALLS_REAL_METHODS)) {
                Method getServiceProvider =
                        authzEndpointObject.getClass().getDeclaredMethod("getServiceProvider", String.class);
                getServiceProvider.setAccessible(true);

                ServiceProvider sp = new ServiceProvider();
                sp.setApplicationName(APP_NAME);
                mockEndpointUtil(false, endpointUtil);

                mockApplicationManagementService(sp);

                identityTenantUtil.when(() -> IdentityTenantUtil.getTenantDomain(anyInt()))
                        .thenReturn(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
                identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString()))
                        .thenReturn(MultitenantConstants.SUPER_TENANT_ID);

                if (e instanceof IdentityOAuth2ClientException) {
                    when(tokenPersistenceProcessor.getPreprocessedClientSecret(anyString())).thenThrow(e);
                }

                if (e instanceof IdentityApplicationManagementException) {
                    ApplicationManagementService appMgtService = mock(ApplicationManagementService.class);
                    OAuth2ServiceComponentHolder.setApplicationMgtService(appMgtService);
                    when(appMgtService.getServiceProviderByClientId(anyString(), any(), anyString())).thenThrow(e);
                }
                try {
                    ServiceProvider result = (ServiceProvider) getServiceProvider.invoke(authzEndpointObject, clientId);
                    assertEquals(result.getApplicationName(), APP_NAME);
                } catch (Exception e1) {
                    if (e == null && CLIENT_ID_VALUE.equals(clientId)) {
                        fail("Unexpected Exception");
                    }
                }
            }
        }
    }

    @DataProvider(name = "provideHandleMaxAgeParameterData")
    public Object[][] provideHandleMaxAgeParameterData() {

        return new Object[][]{
                {"invalidValue", true}
        };
    }

    @Test(dataProvider = "provideHandleMaxAgeParameterData")
    public void testHandleMaxAgeParameter(String value, Boolean state) throws Exception {

        Method handleMaxAgeParameter =
                authzEndpointObject.getClass().getDeclaredMethod("handleMaxAgeParameter",
                        OAuthAuthzRequest.class, OAuth2Parameters.class);
        handleMaxAgeParameter.setAccessible(true);

        OAuth2Parameters oAuth2Parameters = new OAuth2Parameters();
        when(oAuthAuthzRequest.getParam(OAuthConstants.OIDCClaims.MAX_AGE)).thenReturn(value);

        try {
            handleMaxAgeParameter.invoke(authzEndpointObject, oAuthAuthzRequest, oAuth2Parameters);
        } catch (Exception e1) {
            assertTrue(state);
        }
    }

    @DataProvider(name = "provideHandleOAuthAuthorizationRequest1Data")
    public Object[][] provideHandleOAuthAuthorizationRequest1Data() {

        ServiceProvider sp1 = new ServiceProvider();
        ServiceProvider sp2 = new ServiceProvider();
        ServiceProvider sp3 = new ServiceProvider();
        ServiceProviderProperty property1 = new ServiceProviderProperty();
        property1.setName(SP_DISPLAY_NAME);
        property1.setValue("myApplication");
        ServiceProviderProperty property2 = new ServiceProviderProperty();
        property2.setName(SP_NAME);
        property2.setValue(APP_NAME);

        ServiceProviderProperty[] properties1 = new ServiceProviderProperty[]{property1, property2};
        sp1.setSpProperties(properties1);
        ServiceProviderProperty[] properties2 = new ServiceProviderProperty[]{property2};
        sp2.setSpProperties(properties2);

        return addDiagnosticLogStatusToExistingDataProvider(new Object[][]{
                {true, sp1, "myApplication"},
                {true, sp2, null},
                {true, sp3, null},
                {false, sp1, null},
        });
    }

    @Test(dataProvider = "provideHandleOAuthAuthorizationRequest1Data", groups = "testWithConnection")
    public void testHandleOAuthAuthorizationRequest1(boolean showDisplayName, Object spObj, String savedDisplayName,
                                                     boolean diagnosticLogsEnabled)
            throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration =
                     mockStatic(OAuthServerConfiguration.class);
             MockedStatic<OAuthServerConfigurationFactory> oAuthServerConfigurationFactory =
                     mockStatic(OAuthServerConfigurationFactory.class);
             MockedStatic<SSOConsentServiceFactory> ssoConsentServiceFactory =
                     mockStatic(SSOConsentServiceFactory.class)) {
            ssoConsentServiceFactory.when(SSOConsentServiceFactory::getSSOConsentService)
                    .thenReturn(mockedSSOConsentService);
            oAuthServerConfigurationFactory.when(OAuthServerConfigurationFactory::getOAuthServerConfiguration)
                    .thenReturn(mockOAuthServerConfiguration);
            mockSSOConsentService(false);
            mockOAuthServerConfiguration(oAuthServerConfiguration);
            try (MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
                 MockedStatic<LoggerUtils> loggerUtils = mockStatic(LoggerUtils.class);
                 MockedStatic<CentralLogMgtServiceComponentHolder> centralLogMgtServiceComponentMock =
                         mockStatic(CentralLogMgtServiceComponentHolder.class);
                 MockedStatic<SessionDataCache> sessionDataCache = mockStatic(SessionDataCache.class);
                 MockedStatic<EndpointUtil> endpointUtil = mockStatic(EndpointUtil.class, Mockito.CALLS_REAL_METHODS);
                 MockedStatic<OAuth2ServiceFactory> oAuth2ServiceFactory = mockStatic(OAuth2ServiceFactory.class);
                 MockedStatic<Oauth2ScopeServiceFactory> oAuth2ScopeServiceFactory =
                         mockStatic(Oauth2ScopeServiceFactory.class)) {

                oAuth2ScopeServiceFactory.when(Oauth2ScopeServiceFactory::getOAuth2ScopeService)
                        .thenReturn(oAuth2ScopeService);
                ServiceProvider sp = (ServiceProvider) spObj;
                sp.setApplicationName(APP_NAME);

                oAuth2ServiceFactory.when(OAuth2ServiceFactory::getOAuth2Service).thenReturn(oAuth2Service);
                mockApplicationManagementService(sp);

                mockEndpointUtil(false, endpointUtil);

                identityTenantUtil.when(() -> IdentityTenantUtil.getTenantDomain(anyInt()))
                        .thenReturn(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
                identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString()))
                        .thenReturn(MultitenantConstants.SUPER_TENANT_ID);
                loggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(diagnosticLogsEnabled);
                IdentityEventService eventServiceMock = mock(IdentityEventService.class);

                centralLogMgtServiceComponentMock.when(
                                CentralLogMgtServiceComponentHolder::getInstance)
                        .thenReturn(centralLogMgtServiceComponentHolderMock);
                when(centralLogMgtServiceComponentHolderMock.getIdentityEventService()).thenReturn(eventServiceMock);
                doNothing().when(eventServiceMock).handleEvent(any());

                Map<String, String[]> requestParams = new HashMap<>();
                Map<String, Object> requestAttributes = new HashMap<>();

                requestParams.put(CLIENT_ID, new String[]{CLIENT_ID_VALUE});

                requestParams.put(REDIRECT_URI, new String[]{APP_REDIRECT_URL});
                requestParams.put(OAuth.OAUTH_RESPONSE_TYPE, new String[]{ResponseType.TOKEN.toString()});

                mockHttpRequest(requestParams, requestAttributes, HttpMethod.POST);

                OAuth2ClientValidationResponseDTO validationResponseDTO = new OAuth2ClientValidationResponseDTO();
                validationResponseDTO.setValidClient(true);
                validationResponseDTO.setCallbackURL(APP_REDIRECT_URL);
                when(oAuth2Service.validateClientInfo(any())).thenReturn(validationResponseDTO);

                Map<String, Class<? extends OAuthValidator<HttpServletRequest>>> responseTypeValidators =
                        new Hashtable<>();
                responseTypeValidators.put(ResponseType.CODE.toString(), CodeValidator.class);
                responseTypeValidators.put(ResponseType.TOKEN.toString(), TokenValidator.class);

                when(mockOAuthServerConfiguration.getSupportedResponseTypeValidators()).thenReturn(
                        responseTypeValidators);
                when(mockOAuthServerConfiguration.isShowDisplayNameInConsentPage()).thenReturn(showDisplayName);

                Method handleOAuthAuthorizationRequest = authzEndpointObject.getClass().getDeclaredMethod(
                        "handleOAuthAuthorizationRequest", OAuthMessage.class);
                handleOAuthAuthorizationRequest.setAccessible(true);

                SessionDataCache mockSessionDataCache = mock(SessionDataCache.class);
                sessionDataCache.when(SessionDataCache::getInstance).thenReturn(mockSessionDataCache);
                final SessionDataCacheEntry[] cacheEntry = new SessionDataCacheEntry[1];
                doAnswer((Answer<Object>) invocation -> {

                    cacheEntry[0] = (SessionDataCacheEntry) invocation.getArguments()[1];
                    return null;
                }).when(mockSessionDataCache)
                        .addToCache(any(SessionDataCacheKey.class), any(SessionDataCacheEntry.class));

                when(oAuthMessage.getRequest()).thenReturn(httpServletRequest);
                when(oAuthMessage.getClientId()).thenReturn(CLIENT_ID_VALUE);
                handleOAuthAuthorizationRequest.invoke(authzEndpointObject, oAuthMessage);
                assertNotNull(cacheEntry[0], "Parameters not saved in cache");
                assertEquals(cacheEntry[0].getoAuth2Parameters().getDisplayName(), savedDisplayName);
            }
        }
    }

    @BeforeMethod
    public void setupKeystore() throws Exception {

        clientKeyStore = getKeyStoreFromFile("testkeystore.jks", "wso2carbon",
                System.getProperty(CarbonBaseConstants.CARBON_HOME));
    }

    @DataProvider(name = "provideHandleRequestObjectData")
    public Object[][] provideHandleRequestObjectData() throws Exception {

        OAuth2Parameters oAuth2Parameters = new OAuth2Parameters();
        oAuth2Parameters.setClientId(TestConstants.CLIENT_ID);
        oAuth2Parameters.setRedirectURI(TestConstants.CALLBACK);
        oAuth2Parameters.setTenantDomain(TestConstants.TENANT_DOMAIN);
        oAuth2Parameters.setNonce("nonceInParams");
        oAuth2Parameters.setState("stateInParams");
        oAuth2Parameters.setPrompt("promptInParams");

        Map<String, Object> defaultClaims = new HashMap<>();
        defaultClaims.put(OAuthConstants.OAuth20Params.REDIRECT_URI, TestConstants.CALLBACK);
        defaultClaims.put(NBF, System.currentTimeMillis() / MILLISECONDS_PER_SECOND);
        defaultClaims.put(EXP, System.currentTimeMillis() / MILLISECONDS_PER_SECOND + TIME_MARGIN_IN_SECONDS);
        defaultClaims.put(OAuthConstants.OAuth20Params.SCOPE, TestConstants.SCOPE_STRING);
        defaultClaims.put(OAuthConstants.OAuth20Params.NONCE, "nonceInRequestObject");

        Map<String, Object> claims1 = new HashMap<>(defaultClaims);
        claims1.put(OAuthConstants.STATE, "stateInRequestObject");
        claims1.put(OAuthConstants.OAuth20Params.PROMPT, "promptInRequestObject");

        return new Object[][]{
                {true, SerializationUtils.clone(oAuth2Parameters), claims1,
                        "Test override claims from request object."},
                {true, SerializationUtils.clone(oAuth2Parameters), defaultClaims,
                        "Test ignore claims outside request object."}, // No overridable claims sent in the req obj.
                {false, SerializationUtils.clone(oAuth2Parameters), defaultClaims,
                        "Test request without request object."}
        };
    }

    @Test(dataProvider = "provideHandleRequestObjectData")
    public void testHandleOIDCRequestObjectForFAPI(boolean withRequestObject, Object oAuth2ParametersObj,
                                                   Map<String, Object> claims,
                                                   String testName) throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class)) {
            mockSSOConsentService(false);
            mockOAuthServerConfiguration(oAuthServerConfiguration);
            try (MockedStatic<LoggerUtils> loggerUtils = mockStatic(LoggerUtils.class);
                 MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class, Mockito.CALLS_REAL_METHODS);
                 MockedStatic<EndpointUtil> endpointUtil = mockStatic(EndpointUtil.class, Mockito.CALLS_REAL_METHODS)) {

                OAuth2Parameters oAuth2Parameters = (OAuth2Parameters) oAuth2ParametersObj;
                OAuth2Parameters originalOAuth2Parameters = SerializationUtils.clone(oAuth2Parameters);

                Key privateKey = clientKeyStore.getKey("wso2carbon", "wso2carbon".toCharArray());

                if (withRequestObject) {
                    String jsonWebToken =
                            buildJWTWithExpiry(oAuth2Parameters.getClientId(), oAuth2Parameters.getClientId(), "1000",
                                    "audience",
                                    JWSAlgorithm.PS256.getName(),
                                    privateKey, 0, claims, 3600 * 1000);
                    when(oAuthAuthzRequest.getParam(OAuthConstants.OAuth20Params.REQUEST)).thenReturn(jsonWebToken);
                }

                Map<String, RequestObjectBuilder> requestObjectBuilderMap = new HashMap<>();
                requestObjectBuilderMap.put(REQUEST_PARAM_VALUE_BUILDER, new RequestParamRequestObjectBuilder());
                RequestObjectValidatorImpl requestObjectValidator = spy(new RequestObjectValidatorImpl());
                doReturn(true).when(requestObjectValidator).validateSignature(any(), any());
                doReturn(true).when(requestObjectValidator).validateRequestObject(any(), any());

                when((mockOAuthServerConfiguration.getRequestObjectBuilders())).thenReturn(requestObjectBuilderMap);
                when((mockOAuthServerConfiguration.getRequestObjectValidator())).thenReturn(requestObjectValidator);

                loggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(false);

                OAuthAppDO appDO = new OAuthAppDO();
                appDO.setRequestObjectSignatureValidationEnabled(false);
                appDO.setRequirePushedAuthorizationRequests(false);
                oAuth2Util.when(() -> OAuth2Util.getAppInformationByClientId(oAuth2Parameters.getClientId()))
                        .thenReturn(appDO);
                oAuth2Util.when(() -> OAuth2Util.getAppInformationByClientId(oAuth2Parameters.getClientId(),
                        oAuth2Parameters.getTenantDomain())).thenReturn(appDO);
                oAuth2Util.when(() -> OAuth2Util.isFapiConformantApp(any())).thenReturn(true);

                mockEndpointUtil(false, endpointUtil);
                when(oAuth2Service.isPKCESupportEnabled()).thenReturn(false);

                Assert.assertEquals(oAuth2Parameters.getNonce(), originalOAuth2Parameters.getNonce());
                Assert.assertEquals(oAuth2Parameters.getState(), originalOAuth2Parameters.getState());
                Assert.assertEquals(oAuth2Parameters.getPrompt(), originalOAuth2Parameters.getPrompt());

                Method handleOIDCRequestObject = authzEndpointObject.getClass().getDeclaredMethod(
                        "handleOIDCRequestObject", OAuthMessage.class, OAuthAuthzRequest.class, OAuth2Parameters.class);
                handleOIDCRequestObject.setAccessible(true);
                try {
                    handleOIDCRequestObject.invoke(authzEndpointObject, oAuthMessage, oAuthAuthzRequest,
                            oAuth2Parameters);
                    Assert.assertEquals(oAuth2Parameters.getNonce(), claims.get(OAuthConstants.OAuth20Params.NONCE),
                            testName);
                    Assert.assertEquals(oAuth2Parameters.getState(), claims.get(OAuthConstants.OAuth20Params.STATE),
                            testName);
                    Assert.assertEquals(oAuth2Parameters.getPrompt(), claims.get(OAuthConstants.OAuth20Params.PROMPT),
                            testName);
                } catch (InvocationTargetException e) {
                    Assert.assertEquals(e.getTargetException().getMessage(),
                            "Request Object is mandatory for FAPI Conformant Applications.", testName);
                }
            }
        }
    }

    private static KeyStore getKeyStoreFromFile(String keystoreName, String password, String home) throws Exception {

        Path tenantKeystorePath = Paths.get(home, "repository", "resources", "security", keystoreName);
        FileInputStream file = new FileInputStream(tenantKeystorePath.toString());
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(file, password.toCharArray());
        return keystore;
    }

    private static String buildJWTWithExpiry(String issuer, String subject, String jti, String audience, String
            algorithm, Key privateKey, long notBeforeMillis, Map<String, Object> claims, long lifetimeInMillis)
            throws RequestObjectException {

        JWTClaimsSet jwtClaimsSet = getJwtClaimsSet(issuer, subject, jti, audience, notBeforeMillis, claims,
                lifetimeInMillis);
        if (JWSAlgorithm.NONE.getName().equals(algorithm)) {
            return new PlainJWT(jwtClaimsSet).serialize();
        }

        return signJWTWithRSA(jwtClaimsSet, privateKey, JWSAlgorithm.parse(algorithm));
    }

    private static String signJWTWithRSA(JWTClaimsSet jwtClaimsSet, Key privateKey, JWSAlgorithm jwsAlgorithm)
            throws RequestObjectException {

        try {
            JWSSigner signer = new RSASSASigner((RSAPrivateKey) privateKey);
            SignedJWT signedJWT = new SignedJWT(new JWSHeader(jwsAlgorithm), jwtClaimsSet);
            signer.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
            signedJWT.sign(signer);
            return signedJWT.serialize();
        } catch (JOSEException e) {
            throw new RequestObjectException("error_signing_jwt", "Error occurred while signing JWT.");
        }
    }

    private static JWTClaimsSet getJwtClaimsSet(String issuer, String subject, String jti, String audience, long
            notBeforeMillis, Map<String, Object> claims, long lifetimeInMillis) {

        long curTimeInMillis = Calendar.getInstance().getTimeInMillis();
        // Set claims to jwt token.
        JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
        jwtClaimsSetBuilder.issuer(issuer);
        jwtClaimsSetBuilder.subject(subject);
        jwtClaimsSetBuilder.audience(Arrays.asList(audience));
        jwtClaimsSetBuilder.jwtID(jti);
        jwtClaimsSetBuilder.expirationTime(new Date((curTimeInMillis + lifetimeInMillis)));
        jwtClaimsSetBuilder.issueTime(new Date(curTimeInMillis));

        if (notBeforeMillis > 0) {
            jwtClaimsSetBuilder.notBeforeTime(new Date(curTimeInMillis + notBeforeMillis));
        }
        if (claims != null && !claims.isEmpty()) {
            for (Map.Entry entry : claims.entrySet()) {
                jwtClaimsSetBuilder.claim(entry.getKey().toString(), entry.getValue());
            }
        }
        return jwtClaimsSetBuilder.build();
    }

    @Test(dependsOnGroups = "testWithConnection")
    public void testIdentityOAuthAdminException() throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);
            MockedStatic<OAuthServerConfigurationFactory> oAuthServerConfigurationFactory =
                mockStatic(OAuthServerConfigurationFactory.class);) {

            oAuthServerConfigurationFactory.when(OAuthServerConfigurationFactory::getOAuthServerConfiguration)
                    .thenReturn(mockOAuthServerConfiguration);
            mockSSOConsentService(false);
            mockOAuthServerConfiguration(oAuthServerConfiguration);
            try (MockedStatic<LoggerUtils> loggerUtils = mockStatic(LoggerUtils.class);
                 MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
                 MockedStatic<OAuth2Util.OAuthURL> oAuthURL = mockStatic(OAuth2Util.OAuthURL.class);
                 MockedStatic<EndpointUtil> endpointUtil = mockStatic(EndpointUtil.class, Mockito.CALLS_REAL_METHODS);
                 MockedStatic<OAuth2ServiceFactory> oAuth2ServiceFactory = mockStatic(OAuth2ServiceFactory.class)) {

                oAuth2ServiceFactory.when(OAuth2ServiceFactory::getOAuth2Service).thenReturn(oAuth2Service);
                //OAuthAdminException will not occur due to introduce a new Service to get the App State instead
                // directly use dao
                Map<String, String[]> requestParams = new HashMap<>();
                Map<String, Object> requestAttributes = new HashMap<>();

                requestParams.put(CLIENT_ID, new String[]{CLIENT_ID_VALUE});
                requestParams.put(FrameworkConstants.RequestParams.TO_COMMONAUTH, new String[]{"false"});
                requestAttributes.put(FrameworkConstants.RequestParams.FLOW_STATUS,
                        AuthenticatorFlowStatus.SUCCESS_COMPLETED);
                mockHttpRequest(requestParams, requestAttributes, HttpMethod.POST);

                loggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(true);
                identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString()))
                        .thenReturn(MultitenantConstants.SUPER_TENANT_ID);
                identityTenantUtil.when(IdentityTenantUtil::getLoginTenantId)
                        .thenReturn(MultitenantConstants.SUPER_TENANT_ID);

                Connection connection1 = getConnection(); // Closing connection to create SQLException
                connection1.close();
                identityDatabaseUtil.when(
                        IdentityDatabaseUtil::getDBConnection).thenAnswer(invocationOnMock -> connection1);
                identityDatabaseUtil.when(() -> IdentityDatabaseUtil.getDBConnection(false))
                        .thenAnswer(invocationOnMock -> connection1);
                mockEndpointUtil(false, endpointUtil);
                oAuthURL.when(OAuth2Util.OAuthURL::getOAuth2ErrorPageUrl).thenReturn(ERROR_PAGE_URL);
                when(oAuth2Service.getOauthApplicationState(CLIENT_ID_VALUE)).thenReturn("ACTIVE");
                doCallRealMethod().when(oAuth2Service).validateInputParameters(httpServletRequest);

                Response response;
                try {
                    response = oAuth2AuthzEndpoint.authorize(httpServletRequest, httpServletResponse);
                } catch (InvalidRequestParentException ire) {
                    InvalidRequestExceptionMapper invalidRequestExceptionMapper = new InvalidRequestExceptionMapper();
                    response = invalidRequestExceptionMapper.toResponse(ire);
                }

                assertEquals(response.getStatus(), HttpServletResponse.SC_FOUND);
            }
        }
    }

    private void mockHttpRequest(final Map<String, String[]> requestParams,
                                 final Map<String, Object> requestAttributes, String method) {

        doAnswer((Answer<Object>) invocation -> {

            String key = (String) invocation.getArguments()[0];
            return requestParams.get(key) != null ? requestParams.get(key)[0] : null;
        }).when(httpServletRequest).getParameter(anyString());

        doAnswer((Answer<Object>) invocation -> {

            String key = (String) invocation.getArguments()[0];
            return requestAttributes.get(key);
        }).when(httpServletRequest).getAttribute(anyString());

        doAnswer((Answer<Object>) invocation -> {

            String key = (String) invocation.getArguments()[0];
            Object value = invocation.getArguments()[1];
            requestAttributes.put(key, value);
            return null;
        }).when(httpServletRequest).setAttribute(anyString(), any());

        when(httpServletRequest.getParameterMap()).thenReturn(requestParams);
        when(httpServletRequest.getParameterNames()).thenReturn(Collections.enumeration(requestAttributes.keySet()));
        when(httpServletRequest.getSession()).thenReturn(httpSession);
        when(httpServletRequest.getMethod()).thenReturn(method);
        when(httpServletRequest.getContentType()).thenReturn(OAuth.ContentType.URL_ENCODED);

        String authHeader =
                "Basic Y2ExOWE1NDBmNTQ0Nzc3ODYwZTQ0ZTc1ZjYwNWQ5Mjc6ODduOWE1NDBmNTQ0Nzc3ODYwZTQ0ZTc1ZjYwNWQ0MzU=";
        when(httpServletRequest.getHeader("Authorization")).thenReturn(authHeader);
    }

    private void mockEndpointUtil(boolean isConsentMgtEnabled, MockedStatic<EndpointUtil> endpointUtil)
            throws Exception {

        endpointUtil.when(() -> EndpointUtil.getSPTenantDomainFromClientId(anyString()))
                .thenReturn(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        endpointUtil.when(() -> EndpointUtil.getUserConsentURL(any(OAuth2Parameters.class),
                anyString(), anyString(), any(OAuthMessage.class), anyString())).thenReturn(USER_CONSENT_URL);

        endpointUtil.when(() -> EndpointUtil.getLoginPageURL(anyString(), anyString(), anyBoolean(),
                anyBoolean(), anySet(), anyMap(), any())).thenReturn(LOGIN_PAGE_URL);

        // TODO: Remove mocking consentUtil and test the consent flow as well
        // https://github.com/wso2/product-is/issues/2679
        SSOConsentService ssoConsentService = mock(SSOConsentService.class);
        when(ssoConsentService
                .getConsentRequiredClaimsWithExistingConsents(any(ServiceProvider.class), any(AuthenticatedUser.class)))
                .thenReturn(new ConsentClaimsData());

        when(ssoConsentService
                .getConsentRequiredClaimsWithoutExistingConsents(any(ServiceProvider.class),
                        any(AuthenticatedUser.class)))
                .thenReturn(new ConsentClaimsData());

        when(ssoConsentService.isSSOConsentManagementEnabled(any())).thenReturn(isConsentMgtEnabled);
    }

    private AuthenticationResult setAuthenticationResult(boolean isAuthenticated, Map<ClaimMapping, String> attributes,
                                                         String errorCode, String errorMsg, String errorUri) {

        AuthenticationResult authResult = new AuthenticationResult();
        authResult.setAuthenticated(isAuthenticated);

        if (!isAuthenticated) {
            authResult.addProperty(FrameworkConstants.AUTH_ERROR_CODE, errorCode);
            authResult.addProperty(FrameworkConstants.AUTH_ERROR_MSG, errorMsg);
            authResult.addProperty(FrameworkConstants.AUTH_ERROR_URI, errorUri);
        }

        AuthenticatedUser subject = new AuthenticatedUser();
        subject.setAuthenticatedSubjectIdentifier(USERNAME);
        subject.setUserName(USERNAME);
        subject.setUserAttributes(attributes);
        subject.setUserId(USER_ID);
        authResult.setSubject(subject);

        return authResult;
    }

    private OAuth2Parameters setOAuth2Parameters(Set<String> scopes, String appName, String responseMode,
                                                 String redirectUri, Set<AuthorizationDetail> authorizationDetails) {

        OAuth2Parameters oAuth2Parameters = new OAuth2Parameters();
        oAuth2Parameters.setScopes(scopes);
        oAuth2Parameters.setResponseMode(responseMode);
        oAuth2Parameters.setRedirectURI(redirectUri);
        oAuth2Parameters.setApplicationName(appName);
        oAuth2Parameters.setAuthorizationDetails(new AuthorizationDetails(authorizationDetails));
        return oAuth2Parameters;
    }

    private void mockOAuthServerConfiguration(MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration)
            throws Exception {

        oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance).thenReturn(mockOAuthServerConfiguration);
        when(mockOAuthServerConfiguration.getPersistenceProcessor()).thenReturn(tokenPersistenceProcessor);
        when(mockOAuthServerConfiguration.isRedirectToRequestedRedirectUriEnabled()).thenReturn(false);
        when(tokenPersistenceProcessor.getProcessedClientId(anyString())).thenAnswer(
                invocation -> invocation.getArguments()[0]);
        when(mockOAuthServerConfiguration.getOAuthAuthzRequestClassName())
                .thenReturn("org.wso2.carbon.identity.oauth2.model.CarbonOAuthAuthzRequest");
    }

    @DataProvider(name = "provideFailedAuthenticationErrorInfo")
    public Object[][] provideFailedAuthenticationErrorInfo() {

        OAuthErrorDTO oAuthErrorDTO = null;
        AuthenticationResult authenticationResult = new AuthenticationResult();
        authenticationResult.addProperty(FrameworkConstants.AUTH_ERROR_URI, null);
        authenticationResult.addProperty(FrameworkConstants.AUTH_ERROR_MSG, null);
        authenticationResult.addProperty(FrameworkConstants.AUTH_ERROR_CODE, null);

        OAuthErrorDTO oAuthErrorDTONull = new OAuthErrorDTO();
        AuthenticationResult authenticationResultEmpty = new AuthenticationResult();

        OAuthErrorDTO oAuthErrorDTOEmpty = new OAuthErrorDTO();
        AuthenticationResult authenticationResultWithURI = new AuthenticationResult();
        authenticationResultWithURI.addProperty(FrameworkConstants.AUTH_ERROR_URI, "http://sample_error_uri.com");
        authenticationResultWithURI.addProperty(FrameworkConstants.AUTH_ERROR_MSG, null);
        authenticationResultWithURI.addProperty(FrameworkConstants.AUTH_ERROR_CODE, null);

        OAuthErrorDTO oAuthErrorDTOEmptyTest = new OAuthErrorDTO();
        AuthenticationResult authenticationResultWithoutErrorcode = new AuthenticationResult();
        authenticationResultWithoutErrorcode.addProperty(FrameworkConstants.AUTH_ERROR_MSG, "OverRiddenMessage2");
        authenticationResultWithoutErrorcode
                .addProperty(FrameworkConstants.AUTH_ERROR_URI, "http://sample_error_uri2.com");
        authenticationResultWithoutErrorcode.addProperty(FrameworkConstants.AUTH_ERROR_CODE, null);

        OAuthErrorDTO oAuthErrorDTOWithDes = new OAuthErrorDTO();
        oAuthErrorDTOWithDes.setErrorDescription("messageFromErrorDTO");
        AuthenticationResult authenticationResultWithURIOnly = new AuthenticationResult();
        authenticationResultWithURIOnly.addProperty(FrameworkConstants.AUTH_ERROR_URI, "http://sample_error_uri3.com");
        authenticationResultWithURIOnly.addProperty(FrameworkConstants.AUTH_ERROR_MSG, null);
        authenticationResultWithURIOnly.addProperty(FrameworkConstants.AUTH_ERROR_CODE, null);

        OAuthErrorDTO oAuthErrorDTOOverWritable = new OAuthErrorDTO();
        oAuthErrorDTOOverWritable.setErrorDescription("messageFromErrorDTO");
        AuthenticationResult authenticationResultOverRiding = new AuthenticationResult();
        authenticationResultOverRiding.addProperty(FrameworkConstants.AUTH_ERROR_MSG, "OverRiddenMessage5");
        authenticationResultOverRiding.addProperty(FrameworkConstants.AUTH_ERROR_URI, "http://sample_error_uri4.com");
        authenticationResultOverRiding.addProperty(FrameworkConstants.AUTH_ERROR_CODE, null);

        return new Object[][]{
                {null, authenticationResult, "login_required", "Authentication required", null},
                {oAuthErrorDTONull, authenticationResultEmpty, "login_required", "Authentication required", null},
                {oAuthErrorDTOEmptyTest, authenticationResultWithURI, "login_required", "Authentication required",
                        "http" +
                                "://sample_error_uri.com"},
                {oAuthErrorDTOEmptyTest, authenticationResultWithoutErrorcode, "login_required", "OverRiddenMessage2",
                        "http" +
                                "://sample_error_uri2.com"},
                {oAuthErrorDTOWithDes, authenticationResultWithURIOnly, "login_required", "messageFromErrorDTO",
                        "http" +
                                "://sample_error_uri3.com"},
                {oAuthErrorDTOOverWritable, authenticationResultOverRiding, "login_required", "OverRiddenMessage5",
                        "http" +
                                "://sample_error_uri4.com"},
        };
    }

    @Test(dataProvider = "provideFailedAuthenticationErrorInfo")
    public void testBuildOAuthProblemException(Object oAuthErrorDTOObject, Object authenticationResultObject
            , String expectedCode, String expectedMessage, String expectedURI) throws Exception {

        OAuthErrorDTO oAuthErrorDTO = (OAuthErrorDTO) oAuthErrorDTOObject;
        AuthenticationResult authenticationResult = (AuthenticationResult) authenticationResultObject;

        Assert.assertEquals(expectedCode, oAuth2AuthzEndpoint.buildOAuthProblemException(authenticationResult,
                oAuthErrorDTO).getError());

        Assert.assertEquals(expectedMessage, oAuth2AuthzEndpoint.buildOAuthProblemException(authenticationResult,
                oAuthErrorDTO).getDescription());

        Assert.assertEquals(expectedURI, oAuth2AuthzEndpoint.buildOAuthProblemException(authenticationResult,
                oAuthErrorDTO).getUri());
    }

    private void mockServiceURLBuilder(MockedStatic<ServiceURLBuilder> serviceURLBuilder) throws URLBuilderException {

        ServiceURLBuilder builder = new ServiceURLBuilder() {

            String path = "";

            @Override
            public ServiceURLBuilder addPath(String... strings) {

                Arrays.stream(strings).forEach(x -> {
                    path += "/" + x;
                });
                return this;
            }

            @Override
            public ServiceURLBuilder addParameter(String s, String s1) {

                return this;
            }

            @Override
            public ServiceURLBuilder setFragment(String s) {

                return this;
            }

            @Override
            public ServiceURLBuilder addFragmentParameter(String s, String s1) {

                return this;
            }

            @Override
            public ServiceURL build() throws URLBuilderException {

                ServiceURL serviceURL = mock(ServiceURL.class);
                when(serviceURL.getAbsolutePublicURL()).thenReturn("https://localhost:9443" + path);
                when(serviceURL.getRelativeInternalURL()).thenReturn(path);
                return serviceURL;
            }
        };

        serviceURLBuilder.when(ServiceURLBuilder::create).thenReturn(builder);
    }

    @DataProvider(name = "provideGetLoginTenantDomainData")
    public Object[][] provideGetLoginTenantDomainData() {

        return addDiagnosticLogStatusToExistingDataProvider(new Object[][]{
                {true, "loginTenantDomain", "loginTenantDomain"},
                {true, "", MultitenantConstants.SUPER_TENANT_DOMAIN_NAME},
                {false, "domain", MultitenantConstants.SUPER_TENANT_DOMAIN_NAME},
        });
    }

    @Test(dataProvider = "provideGetLoginTenantDomainData")
    public void testGetLoginTenantDomain(boolean isTenantedSessionsEnabled, String loginDomain, String expectedDomain,
                                         boolean diagnosticLogsEnabled)
            throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);) {
            mockOAuthServerConfiguration(oAuthServerConfiguration);

            try (MockedStatic<LoggerUtils> loggerUtils = mockStatic(LoggerUtils.class);
                 MockedStatic<FrameworkUtils> frameworkUtils = mockStatic(FrameworkUtils.class);
                 MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
                 MockedStatic<CentralLogMgtServiceComponentHolder> centralLogMgtServiceComponentHolder =
                         mockStatic(CentralLogMgtServiceComponentHolder.class);) {

                loggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(diagnosticLogsEnabled);
                frameworkUtils.when(() -> FrameworkUtils.startTenantFlow(anyString())).thenAnswer(invocation -> null);
                frameworkUtils.when(FrameworkUtils::endTenantFlow).thenAnswer(invocation -> null);
                identityTenantUtil.when(() -> IdentityTenantUtil.getTenantDomain(anyInt()))
                        .thenReturn(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
                identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString()))
                        .thenReturn(MultitenantConstants.SUPER_TENANT_ID);
                IdentityEventService eventServiceMock = mock(IdentityEventService.class);
                centralLogMgtServiceComponentHolder.when(
                                CentralLogMgtServiceComponentHolder::getInstance)
                        .thenReturn(centralLogMgtServiceComponentHolderMock);
                when(centralLogMgtServiceComponentHolderMock.getIdentityEventService()).thenReturn(eventServiceMock);
                doNothing().when(eventServiceMock).handleEvent(any());

                if (isTenantedSessionsEnabled) {
                    identityTenantUtil.when(IdentityTenantUtil::isTenantedSessionsEnabled).thenReturn(true);
                } else {
                    identityTenantUtil.when(IdentityTenantUtil::isTenantedSessionsEnabled).thenReturn(false);
                }

                Map<String, String[]> requestParams = new HashMap<>();
                Map<String, Object> requestAttributes = new HashMap<>();

                requestParams.put(FrameworkConstants.RequestParams.LOGIN_TENANT_DOMAIN, new String[]{loginDomain});
                mockHttpRequest(requestParams, requestAttributes, HttpMethod.POST);

                when(oAuthMessage.getRequest()).thenReturn(httpServletRequest);

                Method getLoginTenantDomain = authzEndpointObject.getClass().getDeclaredMethod(
                        "getLoginTenantDomain", OAuthMessage.class, String.class);
                getLoginTenantDomain.setAccessible(true);

                String tenantDomain =
                        (String) getLoginTenantDomain.invoke(authzEndpointObject, oAuthMessage, CLIENT_ID_VALUE);
                assertEquals(tenantDomain, expectedDomain);
            }
        }
    }

    @DataProvider(name = "provideOAuthProblemExceptionData")
    public Object[][] provideOAuthProblemExceptionData() {

        return new Object[][]{
                {"error", "errorDescription", "state", "http://localhost:8080/redirect?" +
                        "error_description=errorDescription&state=state&error=error", true},
                {null, "errorDescription", "state", "http://localhost:8080/redirect?" +
                        "error_description=errorDescription&state=state&error=invalid_request", true},
                {"error", null, "state", "http://localhost:8080/redirect?error_description=error%2C+state&" +
                        "state=state&error=error", true},
                {"error", "errorDescription", null, "http://localhost:8080/redirect?" +
                        "error_description=errorDescription&error=error", true},
                {"error", "errorDescription", "state", "https://localhost:9443/authenticationendpoint/" +
                        "oauth2_error.do?oauthErrorCode=error&oauthErrorMsg=errorDescription&" +
                        "redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fredirect", false}
        };
    }

    @Test(dataProvider = "provideOAuthProblemExceptionData")
    public void testHandleOAuthProblemException(String error, String description, String state, String expectedUrl,
                                                boolean redirectEnabled) throws Exception {

        Method handleOAuthProblemException = authzEndpointObject.getClass().getDeclaredMethod(
                "handleOAuthProblemException", OAuthMessage.class, OAuthProblemException.class);
        handleOAuthProblemException.setAccessible(true);
        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);) {
            mockOAuthServerConfiguration(oAuthServerConfiguration);
            try (MockedStatic<OAuth2Util.OAuthURL> oAuthURL = mockStatic(OAuth2Util.OAuthURL.class);) {
                when(oAuthMessage.getRequest()).thenReturn(httpServletRequest);
                when(mockOAuthServerConfiguration.isRedirectToRequestedRedirectUriEnabled()).thenReturn(
                        redirectEnabled);
                when(httpServletRequest.getParameter("redirect_uri")).thenReturn(APP_REDIRECT_URL);
                oAuthURL.when(OAuth2Util.OAuthURL::getOAuth2ErrorPageUrl).thenReturn(ERROR_PAGE_URL);
                Response response = (Response) handleOAuthProblemException.invoke(authzEndpointObject, oAuthMessage,
                        OAuthProblemException.error(error).description(description).state(state));
                String location = String.valueOf(response.getMetadata().get(HTTPConstants.HEADER_LOCATION).get(0));
                assertEquals(location, expectedUrl);
            }
        }
    }

    @Test
    public void testPKCEunsupportedflow() throws Exception {

        OAuth2ClientValidationResponseDTO validationResponseDTO = new OAuth2ClientValidationResponseDTO();
        OAuthAppDO oAuthAppDO = new OAuthAppDO();
        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);) {
            mockOAuthServerConfiguration(oAuthServerConfiguration);
            try (MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class);) {
                oAuthAppDO.setPkceMandatory(true);
                when(oAuthMessage.getRequest()).thenReturn(httpServletRequest);
                when(oAuthMessage.getRequest().getParameter(CLIENT_ID)).thenReturn(CLIENT_ID_VALUE);
                when(oAuthMessage.getRequest().getAttribute(OAuthConstants.PKCE_UNSUPPORTED_FLOW)).thenReturn(true);
                oAuth2Util.when(() -> OAuth2Util.getAppInformationByClientId(any())).thenReturn(oAuthAppDO);
                Method method = authzEndpointObject.getClass().getDeclaredMethod(
                        "populateValidationResponseWithAppDetail", OAuthMessage.class,
                        OAuth2ClientValidationResponseDTO.class);
                method.setAccessible(true);
                method.invoke(authzEndpointObject, oAuthMessage, validationResponseDTO);
                //PKCE mandoatory should be false when we set PKCE_UNSUPPORTED_FLOW attribute
                assertEquals(validationResponseDTO.isPkceMandatory(), false);
            }
        }
    }

    private static Object[][] addDiagnosticLogStatusToExistingDataProvider(Object[][] existingData) {

        // Combine original values with diagnostic log status.
        Object[][] combinedValues = new Object[existingData.length * 2][];
        for (int i = 0; i < existingData.length; i++) {
            combinedValues[i * 2] = appendValue(existingData[i], true); // Enable diagnostic logs.
            combinedValues[i * 2 + 1] = appendValue(existingData[i], false); // Disable diagnostic logs.
        }
        return combinedValues;
    }

    private static Object[] appendValue(Object[] originalArray, Object value) {

        Object[] newArray = Arrays.copyOf(originalArray, originalArray.length + 1);
        newArray[originalArray.length] = value;
        return newArray;
    }

    private void setSupportedResponseModes() throws ClassNotFoundException, InstantiationException,
            IllegalAccessException {

        Map<String, ResponseModeProvider> supportedResponseModeProviders = new HashMap<>();
        ResponseModeProvider defaultResponseModeProvider;
        Map<String, String> supportedResponseModeClassNames = new HashMap<>();
        String defaultResponseModeProviderClassName;
        supportedResponseModeClassNames.put(OAuthConstants.ResponseModes.QUERY,
                QueryResponseModeProvider.class.getCanonicalName());
        supportedResponseModeClassNames.put(OAuthConstants.ResponseModes.FRAGMENT,
                FragmentResponseModeProvider.class.getCanonicalName());
        supportedResponseModeClassNames.put(OAuthConstants.ResponseModes.FORM_POST,
                FormPostResponseModeProvider.class.getCanonicalName());
        defaultResponseModeProviderClassName = DefaultResponseModeProvider.class.getCanonicalName();

        for (Map.Entry<String, String> entry : supportedResponseModeClassNames.entrySet()) {
            ResponseModeProvider responseModeProvider = (ResponseModeProvider)
                    Class.forName(entry.getValue()).newInstance();

            supportedResponseModeProviders.put(entry.getKey(), responseModeProvider);
        }

        defaultResponseModeProvider = (ResponseModeProvider)
                Class.forName(defaultResponseModeProviderClassName).newInstance();

        OAuth2ServiceComponentHolder.setResponseModeProviders(supportedResponseModeProviders);
        OAuth2ServiceComponentHolder.setDefaultResponseModeProvider(defaultResponseModeProvider);
    }

    private void mockSSOConsentService(boolean isConsentMgtEnabled) throws SSOConsentServiceException {

        // TODO: Remove mocking consentUtil and test the consent flow as well
        // https://github.com/wso2/product-is/issues/2679
//            SSOConsentService ssoConsentService = mock(SSOConsentService.class);
        when(mockedSSOConsentService
                .getConsentRequiredClaimsWithExistingConsents(any(ServiceProvider.class), any(AuthenticatedUser.class)))
                .thenReturn(new ConsentClaimsData());
        when(mockedSSOConsentService
                .getConsentRequiredClaimsWithoutExistingConsents(any(ServiceProvider.class),
                any(AuthenticatedUser.class))).thenReturn(new ConsentClaimsData());

        when(mockedSSOConsentService.isSSOConsentManagementEnabled(any())).thenReturn(isConsentMgtEnabled);
    }
}
