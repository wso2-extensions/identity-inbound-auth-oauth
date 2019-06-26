/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.identity.oauth2.token;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import org.joda.time.Duration;
import org.mockito.Mock;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AuthorizationGrantHandler;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.CustomClaimsCallbackHandler;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;

import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.reset;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.doAnswer;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.spy;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

@PrepareForTest(
        {
                OAuthServerConfiguration.class,
                OAuth2Util.class
        }
)
public class JWTTokenIssuerTest extends PowerMockIdentityBaseTest {

    // Signature algorithms.
    private static final String NONE = "NONE";
    private static final String SHA256_WITH_RSA = "SHA256withRSA";
    private static final String SHA384_WITH_RSA = "SHA384withRSA";
    private static final String SHA512_WITH_RSA = "SHA512withRSA";
    private static final String SHA256_WITH_HMAC = "SHA256withHMAC";
    private static final String SHA384_WITH_HMAC = "SHA384withHMAC";
    private static final String SHA512_WITH_HMAC = "SHA512withHMAC";
    private static final String SHA256_WITH_EC = "SHA256withEC";
    private static final String SHA384_WITH_EC = "SHA384withEC";
    private static final String SHA512_WITH_EC = "SHA512withEC";

    private static final long DEFAULT_APPLICATION_ACCESS_TOKEN_EXPIRY_TIME = 4600L;
    private static final long DEFAULT_USER_ACCESS_TOKEN_EXPIRY_TIME = 3600L;

    private static final String USER_ACCESS_TOKEN_GRANT_TYPE = "userAccessTokenGrantType";
    private static final String APPLICATION_ACCESS_TOKEN_GRANT_TYPE = "applicationAccessTokenGrantType";
    private static final String DUMMY_CLIENT_ID = "dummyClientID";
    private static final String ID_TOKEN_ISSUER = "idTokenIssuer";
    private static final String EXPIRY_TIME_JWT = "EXPIRY_TIME_JWT";

    @Mock
    private OAuthServerConfiguration oAuthServerConfiguration;

    @BeforeMethod
    public void setUp() throws Exception {
        initMocks(this);
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);
    }

    @AfterMethod
    public void tearDown() throws Exception {
        reset(oAuthServerConfiguration);
    }

    @DataProvider(name = "requestScopesProvider")
    public Object[][] provideRequestScopes() {
        final String[] SCOPES_WITH_AUD = new String[]{"aud", "scope1", "scope1"};
        return new Object[][]{
                {null, Collections.emptyList()},
                {new String[0], Collections.emptyList()},
                {new String[]{"scope1", "scope1"}, Collections.emptyList()},
                {SCOPES_WITH_AUD, Arrays.asList(SCOPES_WITH_AUD)}
        };
    }

    /**
     * Test for Plain JWT Building from {@link OAuthTokenReqMessageContext}
     */
    @Test(dataProvider = "requestScopesProvider")
    public void testBuildJWTTokenFromTokenMsgContext(String requestScopes[],
                                                     List<String> expectedJWTAudiences) throws Exception {

        OAuth2AccessTokenReqDTO accessTokenReqDTO = new OAuth2AccessTokenReqDTO();
        OAuthTokenReqMessageContext reqMessageContext = new OAuthTokenReqMessageContext(accessTokenReqDTO);
        reqMessageContext.setScope(requestScopes);

        JWTTokenIssuer jwtTokenIssuer = getJWTTokenIssuer(NONE);
        String jwtToken = jwtTokenIssuer.buildJWTToken(reqMessageContext);

        PlainJWT plainJWT = PlainJWT.parse(jwtToken);
        assertNotNull(plainJWT);
        assertNotNull(plainJWT.getJWTClaimsSet());
        assertEquals(plainJWT.getJWTClaimsSet().getAudience(), expectedJWTAudiences);
    }

    /**
     * Test for Plain JWT Building from {@link OAuthAuthzReqMessageContext}
     */
    @Test(dataProvider = "requestScopesProvider")
    public void testBuildJWTTokenFromAuthzMsgContext(String requestScopes[],
                                                     List<String> expectedJWTAudiences) throws Exception {

        OAuth2AuthorizeReqDTO authorizeReqDTO = new OAuth2AuthorizeReqDTO();
        OAuthAuthzReqMessageContext authzReqMessageContext = new OAuthAuthzReqMessageContext(authorizeReqDTO);
        authzReqMessageContext.setApprovedScope(requestScopes);

        JWTTokenIssuer jwtTokenIssuer = getJWTTokenIssuer(NONE);
        String jwtToken = jwtTokenIssuer.buildJWTToken(authzReqMessageContext);
        PlainJWT plainJWT = PlainJWT.parse(jwtToken);
        assertNotNull(plainJWT);
        assertNotNull(plainJWT.getJWTClaimsSet());
        assertEquals(plainJWT.getJWTClaimsSet().getAudience(), expectedJWTAudiences);
    }

    private JWTTokenIssuer getJWTTokenIssuer(String signatureAlgorithm) throws IdentityOAuth2Exception {
        when(oAuthServerConfiguration.getSignatureAlgorithm()).thenReturn(signatureAlgorithm);
        JWTTokenIssuer jwtTokenIssuer = spy(new JWTTokenIssuer());

        doAnswer(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocationOnMock) throws Throwable {
                return new JWTClaimsSet.Builder().build();
            }
        }).when(jwtTokenIssuer).createJWTClaimSet(
                any(OAuthAuthzReqMessageContext.class),
                any(OAuthTokenReqMessageContext.class),
                anyString());

        return jwtTokenIssuer;
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testCreateJWTClaimSetForInvalidClient() throws Exception {
        mockStatic(OAuth2Util.class);
        when(OAuth2Util.getAppInformationByClientId(anyString()))
                .thenThrow(new InvalidOAuthClientException("INVALID_CLIENT"));
        when(oAuthServerConfiguration.getSignatureAlgorithm()).thenReturn(SHA256_WITH_HMAC);

        JWTTokenIssuer jwtTokenIssuer = new JWTTokenIssuer();
        jwtTokenIssuer.createJWTClaimSet(null, null, null);
    }

    @DataProvider(name = "createJWTClaimSetDataProvider")
    public Object[][] provideClaimSetData() {
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName("DUMMY_USERNAME");
        authenticatedUser.setTenantDomain("DUMMY_TENANT.COM");
        authenticatedUser.setUserStoreDomain("DUMMY_DOMAIN");

        final String AUTHENTICATED_SUBJECT_IDENTIFIER = authenticatedUser.toString();
        authenticatedUser.setAuthenticatedSubjectIdentifier(AUTHENTICATED_SUBJECT_IDENTIFIER);

        OAuth2AuthorizeReqDTO authorizeReqDTO = new OAuth2AuthorizeReqDTO();
        authorizeReqDTO.setUser(authenticatedUser);
        OAuthAuthzReqMessageContext authzReqMessageContext = new OAuthAuthzReqMessageContext(authorizeReqDTO);

        OAuth2AccessTokenReqDTO tokenReqDTO = new OAuth2AccessTokenReqDTO();
        tokenReqDTO.setGrantType(APPLICATION_ACCESS_TOKEN_GRANT_TYPE);
        OAuthTokenReqMessageContext tokenReqMessageContext = new OAuthTokenReqMessageContext(tokenReqDTO);
        tokenReqMessageContext.setAuthorizedUser(authenticatedUser);
        Calendar cal = Calendar.getInstance(); // creates calendar
        cal.setTime(new Date()); // sets calendar time/date
        cal.add(Calendar.HOUR_OF_DAY, 1); // adds one hour
        tokenReqMessageContext.addProperty(EXPIRY_TIME_JWT, cal.getTime());

        return new Object[][]{
                {
                        authzReqMessageContext,
                        null,
                        AUTHENTICATED_SUBJECT_IDENTIFIER,
                        DEFAULT_USER_ACCESS_TOKEN_EXPIRY_TIME * 1000
                },
                {
                        null,
                        tokenReqMessageContext,
                        AUTHENTICATED_SUBJECT_IDENTIFIER,
                        DEFAULT_APPLICATION_ACCESS_TOKEN_EXPIRY_TIME * 1000
                }
        };
    }

    @Test(dataProvider = "createJWTClaimSetDataProvider")
    public void testCreateJWTClaimSet(Object authzReqMessageContext,
                                      Object tokenReqMessageContext,
                                      String sub,
                                      long expectedExpiry) throws Exception {

        OAuthAppDO appDO = spy(new OAuthAppDO());
        mockGrantHandlers();
        mockCustomClaimsCallbackHandler();
        mockStatic(OAuth2Util.class);
        when(OAuth2Util.getAppInformationByClientId(anyString())).thenReturn(appDO);
        when(OAuth2Util.getIDTokenIssuer()).thenReturn(ID_TOKEN_ISSUER);
        when(OAuth2Util.getIdTokenIssuer(anyString())).thenReturn(ID_TOKEN_ISSUER);
        when(OAuth2Util.getOIDCAudience(anyString(), anyObject())).thenReturn(Collections.singletonList
                (DUMMY_CLIENT_ID));

        when(oAuthServerConfiguration.getSignatureAlgorithm()).thenReturn(SHA256_WITH_HMAC);
        when(oAuthServerConfiguration.getUserAccessTokenValidityPeriodInSeconds())
                .thenReturn(DEFAULT_USER_ACCESS_TOKEN_EXPIRY_TIME);
        when(oAuthServerConfiguration.getApplicationAccessTokenValidityPeriodInSeconds())
                .thenReturn(DEFAULT_APPLICATION_ACCESS_TOKEN_EXPIRY_TIME);

        JWTTokenIssuer jwtTokenIssuer = new JWTTokenIssuer();
        JWTClaimsSet jwtClaimSet = jwtTokenIssuer.createJWTClaimSet(
                (OAuthAuthzReqMessageContext) authzReqMessageContext,
                (OAuthTokenReqMessageContext) tokenReqMessageContext,
                DUMMY_CLIENT_ID
        );

        assertNotNull(jwtClaimSet);
        assertEquals(jwtClaimSet.getIssuer(), ID_TOKEN_ISSUER);
        assertEquals(jwtClaimSet.getSubject(), sub);
        assertEquals(jwtClaimSet.getClaim("azp"), DUMMY_CLIENT_ID);

        // Assert whether client id is among audiences
        assertNotNull(jwtClaimSet.getAudience());
        assertTrue(jwtClaimSet.getAudience().contains(DUMMY_CLIENT_ID));

        // Validate expiry
        assertNotNull(jwtClaimSet.getIssueTime());
        assertNotNull(jwtClaimSet.getExpirationTime());

        if (tokenReqMessageContext != null
                && ((OAuthTokenReqMessageContext) tokenReqMessageContext).getProperty(EXPIRY_TIME_JWT)
                != null) {
            assertTrue(jwtClaimSet.getExpirationTime().compareTo(
                    (Date) ((OAuthTokenReqMessageContext) tokenReqMessageContext)
                            .getProperty(EXPIRY_TIME_JWT)) <= 0);
        } else {
            assertEquals(new Duration(jwtClaimSet.getIssueTime().getTime(), jwtClaimSet.getExpirationTime().getTime())
                    .getMillis(), expectedExpiry);
        }

    }

    @Test
    public void testSignJWTWithRSA() throws Exception {
    }

    @Test
    public void testSignJWTWithHMAC() throws Exception {
        when(oAuthServerConfiguration.getSignatureAlgorithm()).thenReturn(SHA256_WITH_HMAC);
        try {
            new JWTTokenIssuer().signJWTWithHMAC(null, null, null);
            fail("Looks like someone has implemented this method. Need to modify this testcase");
        } catch (IdentityOAuth2Exception ex) {
            assertTrue(ex.getMessage() != null && ex.getMessage().contains("is not supported"),
                    "Looks like someone has implemented this method. Need to modify this testcase");
        }
    }

    @Test
    public void testSignJWTWithECDSA() throws Exception {
        when(oAuthServerConfiguration.getSignatureAlgorithm()).thenReturn(SHA256_WITH_EC);
        try {
            new JWTTokenIssuer().signJWTWithECDSA(null, null, null);
            fail("Looks like someone has implemented this method. Need to modify this testcase");
        } catch (IdentityOAuth2Exception ex) {
            assertTrue(ex.getMessage() != null && ex.getMessage().contains("is not supported"),
                    "Looks like someone has implemented this method. Need to modify this testcase");
        }
    }

    @DataProvider(name = "signatureAlgorithmProvider")
    public Object[][] provideSignatureAlgorithm() {
        return new Object[][]{
                {NONE, JWSAlgorithm.NONE},
                {SHA256_WITH_RSA, JWSAlgorithm.RS256},
                {SHA384_WITH_RSA, JWSAlgorithm.RS384},
                {SHA512_WITH_RSA, JWSAlgorithm.RS512},
                {SHA256_WITH_HMAC, JWSAlgorithm.HS256},
                {SHA384_WITH_HMAC, JWSAlgorithm.HS384},
                {SHA512_WITH_HMAC, JWSAlgorithm.HS512},
                {SHA256_WITH_EC, JWSAlgorithm.ES256},
                {SHA384_WITH_EC, JWSAlgorithm.ES384},
                {SHA512_WITH_EC, JWSAlgorithm.ES512}
        };
    }

    @Test(dataProvider = "signatureAlgorithmProvider")
    public void testMapSignatureAlgorithm(String signatureAlgo,
                                          Object expectedNimbusdsAlgorithm) throws Exception {
        when(oAuthServerConfiguration.getSignatureAlgorithm()).thenReturn(signatureAlgo);

        JWSAlgorithm jwsAlgorithm = new JWTTokenIssuer().mapSignatureAlgorithm(signatureAlgo);
        Assert.assertEquals(jwsAlgorithm, expectedNimbusdsAlgorithm);
    }

    @DataProvider(name = "unsupportedAlgoProvider")
    public Object[][] provideUnsupportedAlgo() {
        return new Object[][]{
                {null},
                {""},
                {"UNSUPPORTED_ALGORITHM"}
        };
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class, dataProvider = "unsupportedAlgoProvider")
    public void testMapSignatureAlgorithmForUnsupportedAlgorithm(String unsupportedAlgorithm) throws Exception {
        when(oAuthServerConfiguration.getSignatureAlgorithm()).thenReturn(unsupportedAlgorithm);

        JWTTokenIssuer jwtTokenIssuer = new JWTTokenIssuer();
        jwtTokenIssuer.mapSignatureAlgorithm("UNSUPPORTED_ALGORITHM");
    }

    @DataProvider(name = "userAccessTokenExpiryTimeProvider")
    public Object[][] provideUserAccessTokenExpiryTime() {
        return new Object[][]{
                // User Access Token Time set at Service Provider level is 0
                {0, DEFAULT_USER_ACCESS_TOKEN_EXPIRY_TIME * 1000},
                // User Access Token Time set at Service Provider level is 8888
                {8888, 8888 * 1000}
        };
    }

    @Test(dataProvider = "userAccessTokenExpiryTimeProvider")
    public void testGetAccessTokenLifeTimeInMillis(long userAccessTokenExpiryTime,
                                                   long expectedAccessTokenLifeTime) throws Exception {

        when(oAuthServerConfiguration.getSignatureAlgorithm()).thenReturn(SHA256_WITH_RSA);
        when(oAuthServerConfiguration.getUserAccessTokenValidityPeriodInSeconds())
                .thenReturn(DEFAULT_USER_ACCESS_TOKEN_EXPIRY_TIME);

        OAuth2AuthorizeReqDTO authorizeReqDTO = new OAuth2AuthorizeReqDTO();
        OAuthAuthzReqMessageContext authzReqMessageContext = new OAuthAuthzReqMessageContext(authorizeReqDTO);

        OAuthAppDO appDO = new OAuthAppDO();
        appDO.setUserAccessTokenExpiryTime(userAccessTokenExpiryTime);
        String consumerKey = "DUMMY_CONSUMER_KEY";

        JWTTokenIssuer jwtTokenIssuer = new JWTTokenIssuer();

        assertEquals(
                jwtTokenIssuer.getAccessTokenLifeTimeInMillis(authzReqMessageContext, appDO, consumerKey),
                expectedAccessTokenLifeTime
        );
    }

    @DataProvider(name = "userAccessTokenExpiryTimeProviderForTokenContext")
    public Object[][] provideUserAccessTokenExpiryTimeForTokenMsgContext() {
        final long USER_ACCESS_TOKEN_LIFE_TIME = 9999L;
        final long APPLICATION_ACCESS_TOKEN_LIFE_TIME = 7777L;
        return new Object[][]{
                // SP level expiry time set for user access token type
                {
                        USER_ACCESS_TOKEN_GRANT_TYPE,
                        USER_ACCESS_TOKEN_LIFE_TIME,
                        APPLICATION_ACCESS_TOKEN_LIFE_TIME,
                        USER_ACCESS_TOKEN_LIFE_TIME * 1000
                },
                // SP level expiry time not set for user access token type
                {
                        USER_ACCESS_TOKEN_GRANT_TYPE,
                        0,
                        APPLICATION_ACCESS_TOKEN_LIFE_TIME,
                        DEFAULT_USER_ACCESS_TOKEN_EXPIRY_TIME * 1000
                },
                // SP level expiry time set for application access token type
                {
                        APPLICATION_ACCESS_TOKEN_GRANT_TYPE,
                        USER_ACCESS_TOKEN_LIFE_TIME,
                        APPLICATION_ACCESS_TOKEN_LIFE_TIME,
                        APPLICATION_ACCESS_TOKEN_LIFE_TIME * 1000
                },
                // SP level expiry time not set for application access token type
                {
                        APPLICATION_ACCESS_TOKEN_GRANT_TYPE,
                        USER_ACCESS_TOKEN_LIFE_TIME,
                        0,
                        DEFAULT_APPLICATION_ACCESS_TOKEN_EXPIRY_TIME * 1000
                }
        };
    }

    @Test(dataProvider = "userAccessTokenExpiryTimeProviderForTokenContext")
    public void testGetAccessTokenLifeTimeInMillis1(String grantType,
                                                    long userAccessTokenExpiryTime,
                                                    long applicationAccessTokenExpiryTime,
                                                    long expectedAccessTokenLifeTime) throws Exception {
        mockGrantHandlers();
        when(oAuthServerConfiguration.getSignatureAlgorithm()).thenReturn(SHA256_WITH_RSA);
        when(oAuthServerConfiguration.getUserAccessTokenValidityPeriodInSeconds())
                .thenReturn(DEFAULT_USER_ACCESS_TOKEN_EXPIRY_TIME);
        when(oAuthServerConfiguration.getApplicationAccessTokenValidityPeriodInSeconds())
                .thenReturn(DEFAULT_APPLICATION_ACCESS_TOKEN_EXPIRY_TIME);

        OAuthAppDO appDO = new OAuthAppDO();
        appDO.setUserAccessTokenExpiryTime(userAccessTokenExpiryTime);
        appDO.setApplicationAccessTokenExpiryTime(applicationAccessTokenExpiryTime);
        String consumerKey = "DUMMY_CONSUMER_KEY";

        OAuth2AccessTokenReqDTO accessTokenReqDTO = new OAuth2AccessTokenReqDTO();
        accessTokenReqDTO.setGrantType(grantType);

        OAuthTokenReqMessageContext tokenReqMessageContext = new OAuthTokenReqMessageContext(accessTokenReqDTO);


        JWTTokenIssuer jwtTokenIssuer = new JWTTokenIssuer();
        assertEquals(
                jwtTokenIssuer.getAccessTokenLifeTimeInMillis(tokenReqMessageContext, appDO, consumerKey),
                expectedAccessTokenLifeTime
        );
    }

    private void mockGrantHandlers() throws IdentityOAuth2Exception {
        AuthorizationGrantHandler userAccessTokenGrantHandler = mock(AuthorizationGrantHandler.class);
        when(userAccessTokenGrantHandler.isOfTypeApplicationUser()).thenReturn(true);

        AuthorizationGrantHandler applicationAccessTokenGrantHandler = mock(AuthorizationGrantHandler.class);
        when(applicationAccessTokenGrantHandler.isOfTypeApplicationUser()).thenReturn(false);

        Map<String, AuthorizationGrantHandler> grantHandlerMap = new HashMap<>();
        grantHandlerMap.put(USER_ACCESS_TOKEN_GRANT_TYPE, userAccessTokenGrantHandler);
        grantHandlerMap.put(APPLICATION_ACCESS_TOKEN_GRANT_TYPE, applicationAccessTokenGrantHandler);

        when(oAuthServerConfiguration.getSupportedGrantTypes()).thenReturn(grantHandlerMap);
    }

    @Test
    public void testHandleCustomClaimsForAuthzMsgContext() throws Exception {
        mockCustomClaimsCallbackHandler();
        when(oAuthServerConfiguration.getSignatureAlgorithm()).thenReturn(SHA256_WITH_RSA);

        JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
        OAuth2AuthorizeReqDTO reqDTO = new OAuth2AuthorizeReqDTO();
        OAuthAuthzReqMessageContext authzReqMessageContext = new OAuthAuthzReqMessageContext(reqDTO);

        JWTTokenIssuer jwtTokenIssuer = new JWTTokenIssuer();
        JWTClaimsSet jwtClaimsSet = jwtTokenIssuer.handleCustomClaims(jwtClaimsSetBuilder, authzReqMessageContext);

        assertNotNull(jwtClaimsSet);
        assertEquals(jwtClaimsSet.getClaims().size(), 1);
        assertNotNull(jwtClaimsSet.getClaim("AUTHZ_CONTEXT_CLAIM"));
    }

    @Test
    public void testHandleCustomClaimsForTokenMsgContext() throws Exception {
        mockCustomClaimsCallbackHandler();
        when(oAuthServerConfiguration.getSignatureAlgorithm()).thenReturn(SHA256_WITH_RSA);
        JWTTokenIssuer jwtTokenIssuer = new JWTTokenIssuer();

        JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
        OAuth2AccessTokenReqDTO tokenReqDTO = new OAuth2AccessTokenReqDTO();
        OAuthTokenReqMessageContext tokenReqMessageContext = new OAuthTokenReqMessageContext(tokenReqDTO);

        JWTClaimsSet jwtClaimsSet = jwtTokenIssuer.handleCustomClaims(jwtClaimsSetBuilder, tokenReqMessageContext);

        assertNotNull(jwtClaimsSet);
        assertEquals(jwtClaimsSet.getClaims().size(), 1);
        assertNotNull(jwtClaimsSet.getClaim("TOKEN_CONTEXT_CLAIM"));
    }

    private void mockCustomClaimsCallbackHandler() {
        CustomClaimsCallbackHandler claimsCallBackHandler = mock(CustomClaimsCallbackHandler.class);

        doAnswer(new Answer<JWTClaimsSet>() {
            @Override
            public JWTClaimsSet answer(InvocationOnMock invocationOnMock) throws Throwable {
                JWTClaimsSet.Builder claimsSetBuilder = invocationOnMock.getArgumentAt(0, JWTClaimsSet.Builder.class);
                claimsSetBuilder.claim("TOKEN_CONTEXT_CLAIM", true);
                return claimsSetBuilder.build();
            }
        }).when(
                claimsCallBackHandler).handleCustomClaims(any(JWTClaimsSet.Builder.class),
                any(OAuthTokenReqMessageContext.class)
        );

        doAnswer(new Answer<JWTClaimsSet>() {
            @Override
            public JWTClaimsSet answer(InvocationOnMock invocationOnMock) throws Throwable {
                JWTClaimsSet.Builder claimsSetBuilder = invocationOnMock.getArgumentAt(0, JWTClaimsSet.Builder.class);
                claimsSetBuilder.claim("AUTHZ_CONTEXT_CLAIM", true);
                return claimsSetBuilder.build();
            }
        }).when(
                claimsCallBackHandler).handleCustomClaims(any(JWTClaimsSet.Builder.class),
                any(OAuthAuthzReqMessageContext.class)
        );

        when(oAuthServerConfiguration.getOpenIDConnectCustomClaimsCallbackHandler()).thenReturn(claimsCallBackHandler);
    }
}