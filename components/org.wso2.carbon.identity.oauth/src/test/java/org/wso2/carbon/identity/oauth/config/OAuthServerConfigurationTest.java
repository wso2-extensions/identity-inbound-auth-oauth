/*
 * Copyright (c) 2017-2024, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth.config;

import org.apache.commons.lang.ArrayUtils;
import org.mockito.MockedStatic;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import java.io.File;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.mockito.Mockito.mockStatic;

/**
 * Unit test covering OAuthServerConfiguration
 */
@WithCarbonHome
public class OAuthServerConfigurationTest {

    private static final String oAuth1RequestTokenUrl
            = "${carbon.protocol}://${carbon.host}:${carbon.management.port}" +
            "/oauth/request-token";
    private static final String oAuth1AuthorizeUrl
            = "${carbon.protocol}://${carbon.host}:${carbon.management.port}" +
            "/oauth/authorize-url";
    private static final String oAuth1AccessTokenUrl
            = "${carbon.protocol}://${carbon.host}:${carbon.management.port}" +
            "/oauth/access-token";
    private static final String oAuth2AuthzEPUrl
            = "${carbon.protocol}://${carbon.host}:${carbon.management.port}" +
            "/oauth2/authorize";
    private static final String oAuth2ParEPUrl
            = "${carbon.protocol}://${carbon.host}:${carbon.management.port}" +
            "/oauth2/par";
    private static final String oAuth2TokenEPUrl
            = "${carbon.protocol}://${carbon.host}:${carbon.management.port}" +
            "/oauth2/token";
    private static final String oAuth2UserInfoEPUrl
            = "${carbon.protocol}://${carbon.host}:${carbon.management.port}" +
            "/oauth2/userinfo";
    private static final String oAuth2RevocationEPUrl
            = "${carbon.protocol}://${carbon.host}:${carbon.management.port}" +
            "/oauth2/revoke";
    private static final String oAuth2IntrospectionEPUrl
            = "${carbon.protocol}://${carbon.host}:${carbon.management.port}" +
            "/oauth2/introspect";
    private static final String oAuth2ConsentPage
            = "${carbon.protocol}://${carbon.host}:${carbon.management.port}" +
            "/authenticationendpoint/oauth2_authz.do";
    private static final String oAuth2ErrorPage
            = "${carbon.protocol}://${carbon.host}:${carbon.management.port}" +
            "/authenticationendpoint/oauth2_error.do";
    private static final String oIDCConsentPage
            = "${carbon.protocol}://${carbon.host}:${carbon.management.port}" +
            "/authenticationendpoint/oauth2_consent.do";
    private static final String oIDCWebFingerEPUrl
            = "${carbon.protocol}://${carbon.host}:${carbon.management.port}" +
            "/.well-known/webfinger";
    private static final String oAuth2DCREPUrl
            = "${carbon.protocol}://${carbon.host}:${carbon.management.port}" +
            "/identity/connect/register";
    private static final String oAuth2JWKSPage
            = "${carbon.protocol}://${carbon.host}:${carbon.management.port}" +
            "/oauth2/jwks";
    private static final String oIDCDiscoveryEPUrl
            = "${carbon.protocol}://${carbon.host}:${carbon.management.port}" +
            "/oauth2/oidcdiscovery";

    @BeforeMethod
    public void setUp() throws Exception {

        System.setProperty("carbon.home", System.getProperty("user.dir"));
        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {

            identityUtil.when(IdentityUtil::getIdentityConfigDirPath)
                    .thenReturn(System.getProperty("user.dir")
                            + File.separator + "src"
                            + File.separator + "test"
                            + File.separator + "resources"
                            + File.separator + "conf");
            Field oAuthServerConfigInstance =
                    OAuthServerConfiguration.class.getDeclaredField("instance");
            oAuthServerConfigInstance.setAccessible(true);
            oAuthServerConfigInstance.set(null, null);

            Field instance = IdentityConfigParser.class.getDeclaredField("parser");
            instance.setAccessible(true);
            instance.set(null, null);
        }
    }

    @Test
    public void testGetInstance() throws Exception {

        Assert.assertNotNull(OAuthServerConfiguration.getInstance(), "Instance is not created");
    }

    @Test
    public void testGetCallbackHandlerMetaData() throws Exception {

        Set<OAuthCallbackHandlerMetaData> metadataSet =
                OAuthServerConfiguration.getInstance().getCallbackHandlerMetaData();
        Assert.assertEquals(metadataSet.toArray()[0]
                        .getClass().getName(),
                "org.wso2.carbon.identity.oauth.config.OAuthCallbackHandlerMetaData",
                "Wrong class type set for metadata class path");
    }

    @Test
    public void testGetOAuth1RequestTokenUrl() throws Exception {

        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {
            identityUtil.when(() -> IdentityUtil.fillURLPlaceholders(oAuth1RequestTokenUrl))
                    .thenReturn(fillURLPlaceholdersForTest(oAuth1RequestTokenUrl));
            identityUtil.when(IdentityUtil::getIdentityConfigDirPath).thenCallRealMethod();
            Assert.assertEquals(OAuthServerConfiguration.getInstance()
                            .getOAuth1RequestTokenUrl(), fillURLPlaceholdersForTest(oAuth1RequestTokenUrl),
                    "Expected value not returned from getter");
        }
    }

    @Test
    public void testGetOAuth1AuthorizeUrl() throws Exception {

        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {
            identityUtil.when(() -> IdentityUtil.fillURLPlaceholders(oAuth1AuthorizeUrl))
                    .thenReturn(fillURLPlaceholdersForTest(oAuth1AuthorizeUrl));
            identityUtil.when(IdentityUtil::getIdentityConfigDirPath).thenCallRealMethod();
            Assert.assertEquals(OAuthServerConfiguration.getInstance()
                            .getOAuth1AuthorizeUrl(), fillURLPlaceholdersForTest(oAuth1AuthorizeUrl),
                    "Expected value not returned from getter");
        }
    }

    @Test
    public void testGetOAuth1AccessTokenUrl() throws Exception {

        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {
            identityUtil.when(() -> IdentityUtil.fillURLPlaceholders(oAuth1AccessTokenUrl))
                    .thenReturn(fillURLPlaceholdersForTest(oAuth1AccessTokenUrl));
            identityUtil.when(IdentityUtil::getIdentityConfigDirPath).thenCallRealMethod();
            Assert.assertEquals(OAuthServerConfiguration.getInstance()
                            .getOAuth1AccessTokenUrl(), fillURLPlaceholdersForTest(oAuth1AccessTokenUrl),
                    "Expected value not returned from getter");
        }
    }

    @Test
    public void testGetOAuth2AuthzEPUrl() throws Exception {

        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {
            identityUtil.when(() -> IdentityUtil.fillURLPlaceholders(oAuth2AuthzEPUrl))
                    .thenReturn(fillURLPlaceholdersForTest(oAuth2AuthzEPUrl));
            identityUtil.when(IdentityUtil::getIdentityConfigDirPath).thenCallRealMethod();
            Assert.assertEquals(OAuthServerConfiguration.getInstance()
                            .getOAuth2AuthzEPUrl(), fillURLPlaceholdersForTest(oAuth2AuthzEPUrl),
                    "Expected value not returned from getter");
        }
    }

    @Test
    public void testGetOAuth2ParEPUrl() throws Exception {

        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {
            identityUtil.when(() -> IdentityUtil.fillURLPlaceholders(oAuth2ParEPUrl))
                    .thenReturn(fillURLPlaceholdersForTest(oAuth2ParEPUrl));
            identityUtil.when(IdentityUtil::getIdentityConfigDirPath).thenCallRealMethod();
            Assert.assertEquals(OAuthServerConfiguration.getInstance()
                            .getOAuth2ParEPUrl(), fillURLPlaceholdersForTest(oAuth2ParEPUrl),
                    "Expected value not returned from getter");
        }
    }

    @Test
    public void testGetOAuth2TokenEPUrl() throws Exception {
        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {
            identityUtil.when(() -> IdentityUtil.fillURLPlaceholders(oAuth2TokenEPUrl))
                    .thenReturn(oAuth2TokenEPUrl);
            identityUtil.when(IdentityUtil::getIdentityConfigDirPath).thenCallRealMethod();
            Assert.assertEquals(OAuthServerConfiguration.getInstance()
                    .getOAuth2TokenEPUrl(), oAuth2TokenEPUrl, "Expected value not returned from getter");
        }
    }

    @Test
    public void testGetOAuth2DCREPUrl() throws Exception {

        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {
            identityUtil.when(() -> IdentityUtil.fillURLPlaceholders(oAuth2DCREPUrl))
                    .thenReturn(oAuth2DCREPUrl);
            identityUtil.when(IdentityUtil::getIdentityConfigDirPath).thenCallRealMethod();
            Assert.assertEquals(OAuthServerConfiguration.getInstance()
                    .getOAuth2DCREPUrl(), oAuth2DCREPUrl, "Expected value not returned from getter");
        }
    }

    @Test
    public void testGetOAuth2JWKSPageUrl() throws Exception {

        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {
            identityUtil.when(() -> IdentityUtil.fillURLPlaceholders(oAuth2JWKSPage))
                    .thenReturn(oAuth2JWKSPage);
            identityUtil.when(IdentityUtil::getIdentityConfigDirPath).thenCallRealMethod();
            Assert.assertEquals(OAuthServerConfiguration.getInstance()
                            .getOAuth2JWKSPageUrl(), oAuth2JWKSPage,
                    "Expected value not returned from getter");
        }
    }

    @Test
    public void testGetOidcDiscoveryUrl() throws Exception {

        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {
            identityUtil.when(() -> IdentityUtil.fillURLPlaceholders(oIDCDiscoveryEPUrl))
                    .thenReturn(oIDCDiscoveryEPUrl);
            identityUtil.when(IdentityUtil::getIdentityConfigDirPath).thenCallRealMethod();
            Assert.assertEquals(OAuthServerConfiguration.getInstance()
                    .getOidcDiscoveryUrl(), oIDCDiscoveryEPUrl, "Expected value not returned from getter");
        }
    }

    @Test
    public void testGetOidcWebFingerEPUrl() throws Exception {

        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {
            identityUtil.when(() -> IdentityUtil.fillURLPlaceholders(oIDCWebFingerEPUrl))
                    .thenReturn(oIDCWebFingerEPUrl);
            identityUtil.when(IdentityUtil::getIdentityConfigDirPath).thenCallRealMethod();
            Assert.assertEquals(OAuthServerConfiguration.getInstance()
                            .getOidcWebFingerEPUrl(), oIDCWebFingerEPUrl,
                    "Expected value not returned from getter");
        }
    }

    @Test
    public void testGetOauth2UserInfoEPUrl() throws Exception {

        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {
            identityUtil.when(() -> IdentityUtil.fillURLPlaceholders(oAuth2UserInfoEPUrl))
                    .thenReturn(oAuth2UserInfoEPUrl);
            identityUtil.when(IdentityUtil::getIdentityConfigDirPath).thenCallRealMethod();
            Assert.assertEquals(OAuthServerConfiguration.getInstance()
                            .getOauth2UserInfoEPUrl(), oAuth2UserInfoEPUrl,
                    "Expected value not returned from getter");
        }
    }

    @Test
    public void testGetOauth2RevocationEPUrl() throws Exception {

        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {
            identityUtil.when(() -> IdentityUtil.fillURLPlaceholders(oAuth2RevocationEPUrl))
                    .thenReturn(oAuth2RevocationEPUrl);
            identityUtil.when(IdentityUtil::getIdentityConfigDirPath).thenCallRealMethod();
            Assert.assertEquals(OAuthServerConfiguration.getInstance()
                            .getOauth2RevocationEPUrl(), oAuth2RevocationEPUrl,
                    "Expected value not returned from getter");
        }
    }

    @Test
    public void testGetOauth2IntrospectionEPUrl() throws Exception {

        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {
            identityUtil.when(() -> IdentityUtil.fillURLPlaceholders(oAuth2IntrospectionEPUrl))
                    .thenReturn(oAuth2IntrospectionEPUrl);
            identityUtil.when(IdentityUtil::getIdentityConfigDirPath).thenCallRealMethod();
            Assert.assertEquals(OAuthServerConfiguration.getInstance()
                            .getOauth2IntrospectionEPUrl(), oAuth2IntrospectionEPUrl,
                    "Expected value not returned from getter");
        }
    }

    @Test
    public void testGetOIDCConsentPageUrl() throws Exception {

        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {
            identityUtil.when(() -> IdentityUtil.fillURLPlaceholders(oIDCConsentPage))
                    .thenReturn(oIDCConsentPage);
            identityUtil.when(IdentityUtil::getIdentityConfigDirPath).thenCallRealMethod();
            Assert.assertEquals(OAuthServerConfiguration.getInstance()
                            .getOIDCConsentPageUrl(), oIDCConsentPage,
                    "Expected value not returned from getter");
        }
    }

    @Test
    public void testGetOauth2ConsentPageUrl() throws Exception {

        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {
            identityUtil.when(() -> IdentityUtil.fillURLPlaceholders(oAuth2ConsentPage))
                    .thenReturn(oAuth2ConsentPage);
            identityUtil.when(IdentityUtil::getIdentityConfigDirPath).thenCallRealMethod();
            Assert.assertEquals(OAuthServerConfiguration.getInstance()
                            .getOauth2ConsentPageUrl(), oAuth2ConsentPage,
                    "Expected value not returned from getter");
        }
    }

    @Test
    public void testGetOauth2ErrorPageUrl() throws Exception {

        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {
        identityUtil.when(() -> IdentityUtil.fillURLPlaceholders(oAuth2ErrorPage))
                .thenReturn(oAuth2ErrorPage);
            identityUtil.when(IdentityUtil::getIdentityConfigDirPath).thenCallRealMethod();
        Assert.assertEquals(OAuthServerConfiguration.getInstance()
                        .getOauth2ErrorPageUrl(), oAuth2ErrorPage,
                "Expected value not returned from getter");
        }
    }

    @Test
    public void testGetOAuthTokenGenerator() throws Exception {

        Assert.assertNotNull(OAuthServerConfiguration.getInstance()
                        .getOAuthTokenGenerator().accessToken(),
                "Expected value not returned from getter");
    }

    @Test
    public void testGetTokenValueGenerator() throws Exception {

        Assert.assertNotNull(OAuthServerConfiguration.getInstance()
                        .getTokenValueGenerator().generateValue(),
                "Expected value not returned from getter");
    }

    @Test
    public void testGetIdentityOauthTokenIssuer() throws Exception {

        Assert.assertNotNull(OAuthServerConfiguration.getInstance().getIdentityOauthTokenIssuer(),
                "Instance is set as null");
    }

    @Test
    public void testGetAuthorizationCodeValidityPeriodInSeconds() throws Exception {

        Assert.assertEquals(OAuthServerConfiguration.getInstance()
                        .getAuthorizationCodeValidityPeriodInSeconds(), 300
                , "Expected value not returned from getter");
    }

    @Test
    public void testGetUserAccessTokenValidityPeriodInSeconds() throws Exception {

        Assert.assertEquals(OAuthServerConfiguration.getInstance()
                        .getUserAccessTokenValidityPeriodInSeconds(), 3600,
                "Expected value not returned from getter");
    }

    @Test
    public void testGetApplicationAccessTokenValidityPeriodInSeconds() throws Exception {

        Assert.assertEquals(OAuthServerConfiguration.getInstance()
                        .getApplicationAccessTokenValidityPeriodInSeconds(), 3600,
                "Expected value not returned from getter");
    }

    @Test
    public void testGetRefreshTokenValidityPeriodInSeconds() throws Exception {

        Assert.assertEquals(OAuthServerConfiguration.getInstance()
                        .getRefreshTokenValidityPeriodInSeconds(), 84600,
                "Expected value not returned from getter");
    }

    @Test
    public void testGetTimeStampSkewInSeconds() throws Exception {

        Assert.assertEquals(OAuthServerConfiguration.getInstance()
                        .getTimeStampSkewInSeconds(), 300,
                "Expected value not returned from getter");
    }

    @Test
    public void testIsCacheEnabled() throws Exception {

        Assert.assertFalse(OAuthServerConfiguration.getInstance().isCacheEnabled(),
                "Expected value not returned from getter");
    }

    @Test
    public void testIsRefreshTokenRenewalEnabled() throws Exception {

        Assert.assertTrue(OAuthServerConfiguration.getInstance()
                .isRefreshTokenRenewalEnabled(), "Expected value not returned from getter");
    }

    @Test
    public void testGetSupportedGrantTypeValidators() throws Exception {

        Assert.assertTrue(OAuthServerConfiguration.getInstance()
                .getSupportedGrantTypeValidators().size() == 5, "Expected value not returned from getter");
    }

    @Test
    public void testGetSupportedResponseTypeValidators() throws Exception {

        Assert.assertTrue(OAuthServerConfiguration.getInstance()
                .getSupportedResponseTypeValidators().size() == 7, "Expected value not returned from getter");
    }

    @Test
    public void testGetSupportedResponseTypes() throws Exception {

        Assert.assertTrue(OAuthServerConfiguration.getInstance()
                .getSupportedResponseTypes().size() == 4, "Expected value not returned from getter");
    }

    @Test
    public void testGetSupportedResponseTypeNames() throws Exception {

        Assert.assertTrue(OAuthServerConfiguration.getInstance()
                .getSupportedResponseTypeNames().size() == 4, "Expected value not returned from getter");
    }

    @Test
    public void testGetSupportedClaims() throws Exception {

        Field claim = OAuthServerConfiguration.class.getDeclaredField("supportedClaims");
        claim.setAccessible(true);
        claim.set(OAuthServerConfiguration.getInstance(), new String[]{"claim1", "claim2"});
        String[] assertClaims = OAuthServerConfiguration.getInstance()
                .getSupportedClaims();
        Assert.assertTrue(ArrayUtils.contains(assertClaims, "claim1") &&
                        ArrayUtils.contains(assertClaims, "claim2"),
                "Set claim does not return properly");
    }

    @Test
    public void testGetSupportedTokenIssuers() throws Exception {
        Assert.assertEquals(OAuthServerConfiguration.getInstance().getSupportedTokenIssuers().size(), 2,
                "Expected value not returned from getter");
    }

    @Test
    public void testGetSAML2TokenCallbackHandler() throws Exception {

        Field callBackHandler = OAuthServerConfiguration.class
                .getDeclaredField("saml2TokenCallbackHandlerName");
        callBackHandler.setAccessible(true);
        callBackHandler.set(OAuthServerConfiguration.getInstance(),
                "org.wso2.carbon.identity.artifacts.SampleTokenCallbackHandler");
        Assert.assertEquals(OAuthServerConfiguration.getInstance()
                        .getSAML2TokenCallbackHandler()
                        .getClass()
                        .getName(),
                "org.wso2.carbon.identity.artifacts.SampleTokenCallbackHandler");
    }

    @Test
    public void testGetTokenValidatorClassNames() throws Exception {

        Map<String, String> tokenClassMap = new HashMap<>();
        tokenClassMap.put("clazz1", "sample.clazz1");
        tokenClassMap.put("clazz2", "sample.clazz2");
        Field callBackHandler = OAuthServerConfiguration.class
                .getDeclaredField("tokenValidatorClassNames");
        callBackHandler.setAccessible(true);
        callBackHandler.set(OAuthServerConfiguration.getInstance(), tokenClassMap);
        Assert.assertEquals(OAuthServerConfiguration.getInstance().getTokenValidatorClassNames(), tokenClassMap);
    }

    @Test
    public void testIsAccessTokenPartitioningEnabled() throws Exception {

        Assert.assertFalse(OAuthServerConfiguration.getInstance()
                .isAccessTokenPartitioningEnabled());
    }

    @Test
    public void testGetSupportedTokenEndpointSigningAlgorithms() {

        List<String> supportedTokenEndpointSigningAlgorithms = OAuthServerConfiguration.getInstance()
                .getSupportedTokenEndpointSigningAlgorithms();
        Assert.assertTrue(supportedTokenEndpointSigningAlgorithms.contains("PS256"));
        Assert.assertTrue(supportedTokenEndpointSigningAlgorithms.contains("ES256"));
        Assert.assertTrue(supportedTokenEndpointSigningAlgorithms.contains("RS256"));
        Assert.assertEquals(supportedTokenEndpointSigningAlgorithms.size(), 3);
    }

    @Test
    public void testIsValidateAuthenticatedUserForRefreshGrantEnabled() throws Exception {

        Assert.assertTrue(OAuthServerConfiguration.getInstance()
                .isValidateAuthenticatedUserForRefreshGrantEnabled());
    }

    private String fillURLPlaceholdersForTest(String url) {

        return url.replace("${carbon.protocol}", "https")
                .replace("${carbon.host}", "localhost")
                .replace("${carbon.management.port}", "9443");
    }
}

