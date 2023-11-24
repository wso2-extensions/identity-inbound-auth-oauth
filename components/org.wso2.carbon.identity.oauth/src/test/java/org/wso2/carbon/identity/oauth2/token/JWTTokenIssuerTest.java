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
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import org.joda.time.Duration;
import org.mockito.Mock;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.OAuth2Constants;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinding;
import org.wso2.carbon.identity.oauth2.token.handlers.claims.JWTAccessTokenClaimProvider;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AuthorizationGrantHandler;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.CustomClaimsCallbackHandler;
import org.wso2.carbon.identity.openidconnect.OIDCClaimUtil;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.interfaces.RSAPrivateKey;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.Assert.assertNull;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyInt;
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
import static org.wso2.carbon.identity.openidconnect.util.TestUtils.getKeyStoreFromFile;

@WithH2Database(files = {"dbScripts/h2.sql", "dbScripts/identity.sql"})
@PrepareForTest(
        {
                OAuthServerConfiguration.class,
                OAuth2Util.class,
                JWTTokenIssuer.class,
                IdentityTenantUtil.class,
                OIDCClaimUtil.class
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
    private static final String DUMMY_SECTOR_IDENTIFIER = "https://mockhost.com/file_of_redirect_uris.json";
    private static final String DUMMY_CONSUMER_KEY = "DUMMY_CONSUMER_KEY";
    private static final String DUMMY_USER_ID = "DUMMY_USER_ID";
    private static final String ID_TOKEN_ISSUER = "idTokenIssuer";
    private static final String EXPIRY_TIME_JWT = "EXPIRY_TIME_JWT";

    private static final long USER_ACCESS_TOKEN_LIFE_TIME = 9999L;
    private static final long APPLICATION_ACCESS_TOKEN_LIFE_TIME = 7777L;

    private static final String CLAIM_CLIENT_ID = "client_id";
    private static final String DEFAULT_TYP_HEADER_VALUE = "at+jwt";
    private static final String THUMBPRINT = "Certificate";
    public static final String AUTHZ_FLOW_CUSTOM_CLAIM = "authz_flow_custom_claim";
    public static final String AUTHZ_FLOW_CUSTOM_CLAIM_VALUE = "authz_flow_custom_claim_value";
    public static final String TOKEN_FLOW_CUSTOM_CLAIM = "token_flow_custom_claim";
    public static final String TOKEN_FLOW_CUSTOM_CLAIM_VALUE = "token_flow_custom_claim_value";

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
        final String[] scopesWithAud = new String[]{"aud", "scope1", "scope1"};
        return new Object[][]{
                {null, Collections.emptyList()},
                {new String[0], Collections.emptyList()},
                {new String[]{"scope1", "scope1"}, Collections.emptyList()},
                {scopesWithAud, Arrays.asList(scopesWithAud)}
        };
    }

    /**
     * Test for Plain JWT Building from {@link OAuthTokenReqMessageContext}
     */
    @Test(dataProvider = "requestScopesProvider")
    public void testBuildJWTTokenFromTokenMsgContext(String requestScopes[],
                                                     List<String> expectedJWTAudiences) throws Exception {

        OAuth2AccessTokenReqDTO accessTokenReqDTO = new OAuth2AccessTokenReqDTO();
        accessTokenReqDTO.setGrantType(USER_ACCESS_TOKEN_GRANT_TYPE);
        accessTokenReqDTO.setClientId(DUMMY_CLIENT_ID);
        OAuthTokenReqMessageContext reqMessageContext = new OAuthTokenReqMessageContext(accessTokenReqDTO);
        reqMessageContext.setScope(requestScopes);
        reqMessageContext.addProperty(OAuthConstants.UserType.USER_TYPE, OAuthConstants.UserType.APPLICATION_USER);
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName("DUMMY_USERNAME");
        authenticatedUser.setTenantDomain("DUMMY_TENANT.COM");
        authenticatedUser.setUserStoreDomain("DUMMY_DOMAIN");
        authenticatedUser.setUserId(DUMMY_USER_ID);
        reqMessageContext.setAuthorizedUser(authenticatedUser);

        TokenBinding tokenBinding = new TokenBinding();
        tokenBinding.setBindingType(OAuth2Constants.TokenBinderType.CERTIFICATE_BASED_TOKEN_BINDER);
        tokenBinding.setBindingReference("test_binding_reference");
        tokenBinding.setBindingValue("R4Hj_0nNdIzVvPdCdsWlxNKm6a74cszp4Za4M1iE8P9");
        reqMessageContext.setTokenBinding(tokenBinding);

        OAuth2ServiceComponentHolder.getInstance().addJWTAccessTokenClaimProvider(
                new DummyTestJWTAccessTokenClaimProvider());
        OAuth2ServiceComponentHolder.getInstance().addJWTAccessTokenClaimProvider(
                new DummyErrornousJWTAccessTokenClaimProvider());

        prepareForBuildJWTToken();
        JWTTokenIssuer jwtTokenIssuer = getJWTTokenIssuer(NONE);
        String jwtToken = jwtTokenIssuer.buildJWTToken(reqMessageContext);

        PlainJWT plainJWT = PlainJWT.parse(jwtToken);
        assertNotNull(plainJWT);
        assertNotNull(plainJWT.getJWTClaimsSet());
        assertEquals(plainJWT.getJWTClaimsSet().getAudience(), expectedJWTAudiences);
        assertNotNull(plainJWT.getJWTClaimsSet().getClaim(TOKEN_FLOW_CUSTOM_CLAIM),
                "Custom claim injected by the claim provider not found.");
        assertEquals(plainJWT.getJWTClaimsSet().getClaim(TOKEN_FLOW_CUSTOM_CLAIM), TOKEN_FLOW_CUSTOM_CLAIM_VALUE,
                "Custom claim value injected by claim provider value mismatch.");
        assertEquals(plainJWT.getJWTClaimsSet().getClaim("binding_type"),
                OAuth2Constants.TokenBinderType.CERTIFICATE_BASED_TOKEN_BINDER);
        assertEquals(plainJWT.getJWTClaimsSet().getClaim("binding_ref"), "test_binding_reference");
        assertEquals(((Map<String, String>) plainJWT.getJWTClaimsSet().getClaim(OAuthConstants.CNF))
                .get(OAuthConstants.X5T_S256), "R4Hj_0nNdIzVvPdCdsWlxNKm6a74cszp4Za4M1iE8P9");
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
        authzReqMessageContext.addProperty(OAuthConstants.UserType.USER_TYPE, OAuthConstants.UserType.APPLICATION_USER);
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName("DUMMY_USERNAME");
        authenticatedUser.setTenantDomain("DUMMY_TENANT.COM");
        authenticatedUser.setUserStoreDomain("DUMMY_DOMAIN");
        authenticatedUser.setUserId(DUMMY_USER_ID);
        authorizeReqDTO.setUser(authenticatedUser);
        authorizeReqDTO.setConsumerKey(DUMMY_CONSUMER_KEY);

        OAuth2ServiceComponentHolder.getInstance().addJWTAccessTokenClaimProvider(
                new DummyTestJWTAccessTokenClaimProvider());
        OAuth2ServiceComponentHolder.getInstance().addJWTAccessTokenClaimProvider(
                new DummyErrornousJWTAccessTokenClaimProvider());

        prepareForBuildJWTToken();
        JWTTokenIssuer jwtTokenIssuer = getJWTTokenIssuer(NONE);
        String jwtToken = jwtTokenIssuer.buildJWTToken(authzReqMessageContext);
        PlainJWT plainJWT = PlainJWT.parse(jwtToken);
        assertNotNull(plainJWT);
        assertNotNull(plainJWT.getJWTClaimsSet());
        assertEquals(plainJWT.getJWTClaimsSet().getAudience(), expectedJWTAudiences);
        assertNotNull(plainJWT.getJWTClaimsSet().getClaim(AUTHZ_FLOW_CUSTOM_CLAIM),
                "Custom claim injected by the claim provider not found.");
        assertEquals(plainJWT.getJWTClaimsSet().getClaim(AUTHZ_FLOW_CUSTOM_CLAIM), AUTHZ_FLOW_CUSTOM_CLAIM_VALUE,
                "Custom claim value injected by claim provider value mismatch.");
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
        when(OAuth2Util.getAppInformationByClientId(null))
                .thenThrow(new InvalidOAuthClientException("INVALID_CLIENT"));
        when(OAuth2Util.isTokenPersistenceEnabled()).thenReturn(true);
        when(oAuthServerConfiguration.getSignatureAlgorithm()).thenReturn(SHA256_WITH_HMAC);
        JWTTokenIssuer jwtTokenIssuer = new JWTTokenIssuer();
        jwtTokenIssuer.createJWTClaimSet(null, null, null);
    }

    @DataProvider(name = "createJWTClaimSetDataProvider")
    public Object[][] provideClaimSetData() {
        AuthenticatedUser authenticatedUserForAuthz = new AuthenticatedUser();
        authenticatedUserForAuthz.setUserName("DUMMY_USERNAME");
        authenticatedUserForAuthz.setTenantDomain("DUMMY_TENANT.COM");
        authenticatedUserForAuthz.setUserStoreDomain("DUMMY_DOMAIN");
        authenticatedUserForAuthz.setUserId(DUMMY_USER_ID);
        authenticatedUserForAuthz.setFederatedUser(true);

        final String authenticatedSubjectIdentifier = authenticatedUserForAuthz.toString();
        authenticatedUserForAuthz.setAuthenticatedSubjectIdentifier(authenticatedSubjectIdentifier);

        OAuth2AuthorizeReqDTO authorizeReqDTO = new OAuth2AuthorizeReqDTO();
        authorizeReqDTO.setTenantDomain("super.wso2");
        authorizeReqDTO.setUser(authenticatedUserForAuthz);
        OAuthAuthzReqMessageContext authzReqMessageContext = new OAuthAuthzReqMessageContext(authorizeReqDTO);
        authzReqMessageContext.addProperty(OAuthConstants.UserType.USER_TYPE, OAuthConstants.UserType.APPLICATION_USER);
        authzReqMessageContext.setConsentedToken(true);

        OAuth2AccessTokenReqDTO tokenReqDTO = new OAuth2AccessTokenReqDTO();
        tokenReqDTO.setGrantType(APPLICATION_ACCESS_TOKEN_GRANT_TYPE);
        tokenReqDTO.setTenantDomain("super.wso2");
        OAuthTokenReqMessageContext tokenReqMessageContext = new OAuthTokenReqMessageContext(tokenReqDTO);
        AuthenticatedUser authenticatedUserForTokenReq = new AuthenticatedUser(authenticatedUserForAuthz);
        tokenReqMessageContext.setAuthorizedUser(authenticatedUserForTokenReq);
        tokenReqMessageContext.setConsentedToken(false);
        Calendar cal = Calendar.getInstance(); // creates calendar
        cal.setTime(new Date()); // sets calendar time/date
        cal.add(Calendar.HOUR_OF_DAY, 1); // adds one hour
        tokenReqMessageContext.addProperty(EXPIRY_TIME_JWT, cal.getTime());
        tokenReqMessageContext.addProperty(OAuthConstants.UserType.USER_TYPE, OAuthConstants.UserType.APPLICATION);
        authenticatedUserForTokenReq.setFederatedUser(false);

        return new Object[][]{
                {
                        authzReqMessageContext,
                        null,
                        authenticatedSubjectIdentifier,
                        DEFAULT_USER_ACCESS_TOKEN_EXPIRY_TIME * 1000,
                        false
                },
                {
                        null,
                        tokenReqMessageContext,
                        authenticatedSubjectIdentifier,
                        DEFAULT_APPLICATION_ACCESS_TOKEN_EXPIRY_TIME * 1000,
                        false
                },
                {
                        authzReqMessageContext,
                        null,
                        authenticatedSubjectIdentifier,
                        DEFAULT_USER_ACCESS_TOKEN_EXPIRY_TIME * 1000,
                        true
                },
                {
                        null,
                        tokenReqMessageContext,
                        authenticatedSubjectIdentifier,
                        DEFAULT_APPLICATION_ACCESS_TOKEN_EXPIRY_TIME * 1000,
                        true
                }
        };
    }

    @Test(dataProvider = "createJWTClaimSetDataProvider")
    public void testCreateJWTClaimSet(Object authzReqMessageContext,
                                      Object tokenReqMessageContext,
                                      String sub,
                                      long expectedExpiry, boolean ppidEnabled) throws Exception {

        OAuthAppDO appDO = spy(new OAuthAppDO());
        appDO.setSubjectType("pairwise");
        appDO.setSectorIdentifierURI(DUMMY_SECTOR_IDENTIFIER);
        appDO.setOauthConsumerKey(DUMMY_CLIENT_ID);
        mockGrantHandlers();
        mockCustomClaimsCallbackHandler();
        mockStatic(OAuth2Util.class);
        when(OAuth2Util.getAppInformationByClientId(anyString())).thenReturn(appDO);
        when(OAuth2Util.getIDTokenIssuer()).thenReturn(ID_TOKEN_ISSUER);
        when(OAuth2Util.getIdTokenIssuer(anyString())).thenReturn(ID_TOKEN_ISSUER);
        when(OAuth2Util.getOIDCAudience(anyString(), anyObject())).thenReturn(Collections.singletonList
                (DUMMY_CLIENT_ID));
        when(OAuth2Util.isTokenPersistenceEnabled()).thenReturn(true);

        when(oAuthServerConfiguration.getSignatureAlgorithm()).thenReturn(SHA256_WITH_HMAC);
        when(oAuthServerConfiguration.getUserAccessTokenValidityPeriodInSeconds())
                .thenReturn(DEFAULT_USER_ACCESS_TOKEN_EXPIRY_TIME);
        when(oAuthServerConfiguration.getApplicationAccessTokenValidityPeriodInSeconds())
                .thenReturn(DEFAULT_APPLICATION_ACCESS_TOKEN_EXPIRY_TIME);

        JWTTokenIssuer jwtTokenIssuer = PowerMockito.spy(new JWTTokenIssuer());
        PowerMockito.doReturn(sub).when(jwtTokenIssuer, "getSubjectClaim", anyString(), anyString(), any());
        PowerMockito.doReturn(ppidEnabled).when(jwtTokenIssuer, "checkPairwiseSubEnabledForAccessTokens");
        PowerMockito.spy(OIDCClaimUtil.class);
        OAuthConstants.SubjectType subjectType = ppidEnabled ? OAuthConstants.SubjectType.PAIRWISE : OAuthConstants
                .SubjectType.PUBLIC;
        PowerMockito.doReturn(subjectType).when(OIDCClaimUtil.class, "getSubjectType", any());
        JWTClaimsSet jwtClaimSet = jwtTokenIssuer.createJWTClaimSet(
                (OAuthAuthzReqMessageContext) authzReqMessageContext,
                (OAuthTokenReqMessageContext) tokenReqMessageContext,
                DUMMY_CLIENT_ID
        );

        assertNotNull(jwtClaimSet);
        assertEquals(jwtClaimSet.getIssuer(), ID_TOKEN_ISSUER);
        String ppidSub = UUID.nameUUIDFromBytes(URI.create(DUMMY_SECTOR_IDENTIFIER).getHost().concat(sub)
                .getBytes(StandardCharsets.UTF_8)).toString();
        assertEquals(jwtClaimSet.getSubject(), ppidEnabled ? ppidSub : sub);
        assertEquals(jwtClaimSet.getClaim("azp"), DUMMY_CLIENT_ID);
        assertEquals(jwtClaimSet.getClaim(CLAIM_CLIENT_ID), DUMMY_CLIENT_ID);

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
                            .getProperty(EXPIRY_TIME_JWT)) >= 0);
        } else {
            assertEquals(new Duration(jwtClaimSet.getIssueTime().getTime(), jwtClaimSet.getExpirationTime().getTime())
                    .getMillis(), expectedExpiry);
        }
        assertNull(jwtClaimSet.getClaim(OAuth2Constants.ENTITY_ID));
        assertNull(jwtClaimSet.getClaim(OAuth2Constants.IS_CONSENTED));
        assertNull(jwtClaimSet.getClaim(OAuth2Constants.IS_FEDERATED));
        // The entity_id claim and is_consented are mandatory claims in the JWT when token persistence is disabled.
        OAuth2ServiceComponentHolder.setConsentedTokenColumnEnabled(true);
        when(OAuth2Util.isTokenPersistenceEnabled()).thenReturn(false);
        jwtClaimSet = jwtTokenIssuer.createJWTClaimSet(
                (OAuthAuthzReqMessageContext) authzReqMessageContext,
                (OAuthTokenReqMessageContext) tokenReqMessageContext,
                DUMMY_CLIENT_ID
        );
        assertNotNull(jwtClaimSet.getClaim(OAuth2Constants.ENTITY_ID));
        assertNotNull(jwtClaimSet.getClaim(OAuth2Constants.IS_CONSENTED));
        assertNotNull(jwtClaimSet.getClaim(OAuth2Constants.IS_FEDERATED));
        if (tokenReqMessageContext != null) {
            assertEquals(jwtClaimSet.getClaim(OAuth2Constants.ENTITY_ID), DUMMY_CLIENT_ID);
            assertEquals(jwtClaimSet.getClaim(OAuth2Constants.IS_CONSENTED), false);
            assertEquals(jwtClaimSet.getClaim(OAuth2Constants.IS_FEDERATED), false);
        }
        if (authzReqMessageContext != null) {
            assertEquals(jwtClaimSet.getClaim(OAuth2Constants.ENTITY_ID), DUMMY_USER_ID);
            assertEquals(jwtClaimSet.getClaim(OAuth2Constants.IS_CONSENTED), true);
            assertEquals(jwtClaimSet.getClaim(OAuth2Constants.IS_FEDERATED), true);
        }
        // Enabling persistence back for the rest of the test cases.
        when(OAuth2Util.isTokenPersistenceEnabled()).thenReturn(true);
    }

    @Test(dataProvider = "createJWTClaimSetDataProvider")
    public void testSignJWTWithRSA(Object authzReqMessageContext,
                                   Object tokenReqMessageContext,
                                   String sub,
                                   long expectedExpiry, boolean ppidEnabled) throws Exception {

            OAuthAppDO appDO = spy(new OAuthAppDO());
            mockGrantHandlers();
            mockCustomClaimsCallbackHandler();
            mockStatic(OAuth2Util.class);
            when(OAuth2Util.getAppInformationByClientId(anyString())).thenReturn(appDO);
            when(OAuth2Util.getThumbPrint(anyString(), anyInt())).thenReturn(THUMBPRINT);
            when(OAuth2Util.isTokenPersistenceEnabled()).thenReturn(true);

            System.setProperty(CarbonBaseConstants.CARBON_HOME,
                    Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString());
            KeyStore wso2KeyStore = getKeyStoreFromFile("wso2carbon.jks", "wso2carbon",
                    System.getProperty(CarbonBaseConstants.CARBON_HOME));
            RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) wso2KeyStore.getKey("wso2carbon", "wso2carbon".toCharArray());

            when((OAuth2Util.getPrivateKey(anyString(), anyInt()))).thenReturn(rsaPrivateKey);
            JWSSigner signer = new RSASSASigner(rsaPrivateKey);
            when(OAuth2Util.createJWSSigner(any())).thenReturn(signer);
            when(oAuthServerConfiguration.getSignatureAlgorithm()).thenReturn(SHA256_WITH_RSA);

            mockStatic(IdentityTenantUtil.class);
            when(IdentityTenantUtil.getTenantId(anyString())).thenReturn(-1234);

            JWTTokenIssuer jwtTokenIssuer = PowerMockito.spy(new JWTTokenIssuer());
            PowerMockito.doReturn(sub).when(jwtTokenIssuer, "getSubjectClaim", anyString(), anyString(), any());
            JWTClaimsSet jwtClaimSet = jwtTokenIssuer.createJWTClaimSet(
                    (OAuthAuthzReqMessageContext) authzReqMessageContext,
                    (OAuthTokenReqMessageContext) tokenReqMessageContext,
                    DUMMY_CLIENT_ID
            );

            String jwtToken = jwtTokenIssuer.signJWT(jwtClaimSet,
                    (OAuthTokenReqMessageContext) tokenReqMessageContext,
                    (OAuthAuthzReqMessageContext) authzReqMessageContext);
            SignedJWT signedJWT = SignedJWT.parse(jwtToken);
            assertNotNull(jwtToken);
            assertNotNull(signedJWT.getHeader());
            assertNotNull(signedJWT.getHeader().getType());
            assertEquals(signedJWT.getHeader().getType().toString(), DEFAULT_TYP_HEADER_VALUE);
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

        JWTTokenIssuer jwtTokenIssuer = new JWTTokenIssuer();

        assertEquals(
                jwtTokenIssuer.getAccessTokenLifeTimeInMillis(authzReqMessageContext, appDO, DUMMY_CONSUMER_KEY),
                expectedAccessTokenLifeTime
        );
    }

    @DataProvider(name = "userAccessTokenExpiryTimeProviderForTokenContext")
    public Object[][] provideUserAccessTokenExpiryTimeForTokenMsgContext() {
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

        OAuth2AccessTokenReqDTO accessTokenReqDTO = new OAuth2AccessTokenReqDTO();
        accessTokenReqDTO.setGrantType(grantType);

        OAuthTokenReqMessageContext tokenReqMessageContext = new OAuthTokenReqMessageContext(accessTokenReqDTO);


        JWTTokenIssuer jwtTokenIssuer = new JWTTokenIssuer();
        assertEquals(
                jwtTokenIssuer.getAccessTokenLifeTimeInMillis(tokenReqMessageContext, appDO, DUMMY_CONSUMER_KEY),
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

    private void mockCustomClaimsCallbackHandler() throws IdentityOAuth2Exception {
        CustomClaimsCallbackHandler claimsCallBackHandler = mock(CustomClaimsCallbackHandler.class);

        doAnswer(new Answer<JWTClaimsSet>() {
            @Override
            public JWTClaimsSet answer(InvocationOnMock invocationOnMock) throws Throwable {
                JWTClaimsSet.Builder claimsSetBuilder = invocationOnMock.getArgument(0);
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
                JWTClaimsSet.Builder claimsSetBuilder = invocationOnMock.getArgument(0);
                claimsSetBuilder.claim("AUTHZ_CONTEXT_CLAIM", true);
                return claimsSetBuilder.build();
            }
        }).when(
                claimsCallBackHandler).handleCustomClaims(any(JWTClaimsSet.Builder.class),
                any(OAuthAuthzReqMessageContext.class)
        );

        when(oAuthServerConfiguration.getOpenIDConnectCustomClaimsCallbackHandler()).
                thenReturn(claimsCallBackHandler);

    }

    private void prepareForBuildJWTToken() throws IdentityOAuth2Exception, InvalidOAuthClientException {

        System.setProperty(CarbonBaseConstants.CARBON_HOME,
                Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString());

        OAuthAppDO appDO = spy(new OAuthAppDO());
        mockGrantHandlers();
        mockCustomClaimsCallbackHandler();
        mockStatic(OAuth2Util.class);
        when(OAuth2Util.getAppInformationByClientId(anyString())).thenReturn(appDO);
        when(OAuth2Util.getTenantDomain(anyInt())).thenReturn("super.wso2");
        when(OAuth2Util.isTokenPersistenceEnabled()).thenReturn(true);
    }

    static class DummyTestJWTAccessTokenClaimProvider implements JWTAccessTokenClaimProvider {

        @Override
        public Map<String, Object> getAdditionalClaims(OAuthAuthzReqMessageContext context)
                throws IdentityOAuth2Exception {

            return Map.of(AUTHZ_FLOW_CUSTOM_CLAIM, AUTHZ_FLOW_CUSTOM_CLAIM_VALUE);
        }

        @Override
        public Map<String, Object> getAdditionalClaims(OAuthTokenReqMessageContext context)
                throws IdentityOAuth2Exception {

            return Map.of(TOKEN_FLOW_CUSTOM_CLAIM, TOKEN_FLOW_CUSTOM_CLAIM_VALUE);
        }
    }

    static class DummyErrornousJWTAccessTokenClaimProvider implements JWTAccessTokenClaimProvider {

        @Override
        public Map<String, Object> getAdditionalClaims(OAuthAuthzReqMessageContext context)
                throws IdentityOAuth2Exception {

            return null;
        }

        @Override
        public Map<String, Object> getAdditionalClaims(OAuthTokenReqMessageContext context)
                throws IdentityOAuth2Exception {

            return null;
        }
    }
}
