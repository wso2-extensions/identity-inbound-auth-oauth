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

package org.wso2.carbon.identity.openidconnect;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWTClaimsSet;
import org.mockito.Mock;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.Assert;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.central.log.mgt.internal.CentralLogMgtServiceComponentHolder;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.common.testng.WithAxisConfiguration;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.common.testng.WithKeyStore;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.oauth.RequestObjectValidatorUtil;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.RequestObjectException;
import org.wso2.carbon.identity.oauth2.TestConstants;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.model.Constants;
import org.wso2.carbon.identity.openidconnect.model.RequestObject;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;

import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.concurrent.TimeUnit;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.powermock.api.mockito.PowerMockito.doReturn;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.spy;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.wso2.carbon.identity.openidconnect.util.TestUtils.buildJWE;
import static org.wso2.carbon.identity.openidconnect.util.TestUtils.buildJWT;
import static org.wso2.carbon.identity.openidconnect.util.TestUtils.buildJWTWithExpiry;
import static org.wso2.carbon.identity.openidconnect.util.TestUtils.getKeyStoreFromFile;
import static org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
import static org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_ID;

@WithKeyStore
@WithAxisConfiguration
@PrepareForTest({RequestObjectValidatorImpl.class, IdentityUtil.class, IdentityTenantUtil.class,
        OAuthServerConfiguration.class, OAuth2Util.class, IdentityProviderManager.class,
        IdentityApplicationManagementUtil.class, LoggerUtils.class, IdentityEventService.class,
        CentralLogMgtServiceComponentHolder.class, RequestObjectValidatorUtil.class})
@PowerMockIgnore({"javax.crypto.*"})
@WithCarbonHome
@WithH2Database(jndiName = "jdbc/WSO2CarbonDB", files = {"dbScripts/identity_req_obj.sql"}, dbName = "testdb2")
public class RequestObjectValidatorImplTest extends PowerMockTestCase {

    public static final String SOME_SERVER_URL = "some-server-url";
    public static final String CLIENT_PUBLIC_CERT_ALIAS = "wso2carbon";
    private RSAPrivateKey rsaPrivateKey;
    private KeyStore clientKeyStore;
    private KeyStore wso2KeyStore;
    public static final String TEST_CLIENT_ID_1 = "wso2test";

    @Mock
    private CentralLogMgtServiceComponentHolder centralLogMgtServiceComponentHolderMock;

    @BeforeTest
    public void setUp() throws Exception {

        System.setProperty(CarbonBaseConstants.CARBON_HOME,
                Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString());
        clientKeyStore =
                getKeyStoreFromFile("testkeystore.jks", CLIENT_PUBLIC_CERT_ALIAS,
                        System.getProperty(CarbonBaseConstants.CARBON_HOME));
        wso2KeyStore = getKeyStoreFromFile("wso2carbon.jks", "wso2carbon", System.getProperty(CarbonBaseConstants
                .CARBON_HOME));
    }

    @DataProvider(name = "provideJWT")
    public Object[][] createJWT() throws Exception {

        Key privateKey = clientKeyStore.getKey("wso2carbon", "wso2carbon".toCharArray());
        PublicKey publicKey = wso2KeyStore.getCertificate("wso2carbon").getPublicKey();
        String audience = SOME_SERVER_URL;

        HashMap<String, Object> claims1 = new HashMap<>();
        claims1.put(Constants.STATE, "af0ifjsldkj");
        HashMap<String, Object> claims2 = new HashMap<>();
        claims2.put(Constants.STATE, "af0ifjsldkj");
        claims2.put(Constants.REDIRECT_URI, TestConstants.CALLBACK);
        claims2.put(Constants.NONCE, "asdrfa");
        claims2.put(Constants.SCOPE, TestConstants.SCOPE_STRING);
        HashMap<String, Object> claims3 = (HashMap<String, Object>) claims2.clone();
        claims3.remove(Constants.NONCE);
        HashMap<String, Object> claims4 = (HashMap<String, Object>) claims2.clone();
        claims4.remove(Constants.SCOPE);
        HashMap<String, Object> claims5 = (HashMap<String, Object>) claims2.clone();
        claims5.remove(Constants.REDIRECT_URI);
        String jsonWebToken1 = buildJWT(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "1000", audience,
                JWSAlgorithm.RS256.getName(), privateKey, 0, claims1);
        String jsonWebToken2 = buildJWT(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "1001", audience, "none", privateKey, 0,
                claims1);
        String jsonWebToken3 = buildJWTWithExpiry(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "1003", audience, "none",
                privateKey, 0, claims1, (-3600 * 1000));
        String jsonWebToken4 = buildJWTWithExpiry(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "1004", audience,
                JWSAlgorithm.RS256.getName(), privateKey, 0, claims1, (-3600 * 1000));
        String jsonWebEncryption1 = buildJWE(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "2000", audience,
                JWSAlgorithm.NONE.getName(), privateKey, publicKey, 0, claims1);
        String jsonWebEncryption2 = buildJWE(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "2001", audience,
                JWSAlgorithm.RS256.getName(), privateKey, publicKey, 0, claims1);
        String jsonWebEncryption3 = buildJWE(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "2001", audience,
                JWSAlgorithm.RS256.getName(), privateKey, publicKey, 0, claims2);
        String jsonWebEncryption4 = buildJWE(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "2001", audience,
                JWSAlgorithm.RS384.getName(), privateKey, publicKey, 0, claims2);
        String jsonWebEncryption5 = buildJWE(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "2000", audience,
                JWSAlgorithm.NONE.getName(), privateKey, publicKey, 0, claims2);
        String jsonWebEncryption6 = buildJWE(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "2000", audience,
                JWSAlgorithm.RS256.getName(), privateKey, publicKey, 0, claims3);
        String jsonWebEncryption7 = buildJWE(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "2000", audience,
                JWSAlgorithm.RS256.getName(), privateKey, publicKey, 0, claims4);
        String jsonWebEncryption8 = buildJWE(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "2000", audience,
                JWSAlgorithm.RS256.getName(), privateKey, publicKey, 0, claims5);
        String jsonWebToken5 = buildJWT(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "1001", audience, "RSA265", privateKey, 0,
                claims1);
        return new Object[][]{
                {jsonWebToken1, true, false, true, true, false, "Valid Request Object, signed not encrypted."},
                {jsonWebToken2, false, false, true, true, false, "Valid Request Object, not xsigned not encrypted."},
                {jsonWebToken3, false, false, true, false, false, "InValid Request Object, expired, not signed not " +
                        "encrypted."},
                {jsonWebToken4, true, false, true, false, false, "InValid Request Object, expired, signed not " +
                        "encrypted."},
                {jsonWebEncryption1, false, true, true, true, false, "Valid Request Object, signed and encrypted."},
                {jsonWebEncryption2, true, true, true, true, false, "Valid Request Object, signed and encrypted."},
                // FAPI tests
                {jsonWebEncryption3, true, true, true, true, true, "FAPI Request Object with a permitted signing " +
                        "algorithm PS256, signed and encrypted."},
                // For testing, PS256, RS256 and ES256 are assumed as permitted algorithms.
                {jsonWebEncryption4, true, true, false, true, true, "FAPI Request Object with an unpermitted signing " +
                        "algorithm RS384, signed and encrypted."},
                {jsonWebEncryption5, false, true, true, true, true, "FAPI Request Object with an unpermitted signing " +
                        "algorithm NONE, signed and encrypted."},
                {jsonWebEncryption6, true, true, true, false, true, "FAPI Request Object without mandatory parameter " +
                        "Nonce."},
                {jsonWebEncryption7, true, true, true, false, true, "Unsigned FAPI Request Object without mandatory " +
                        "parameter Scopes."},
                {jsonWebEncryption8, true, true, true, false, true, "Unsigned FAPI Request Object without mandatory " +
                        "parameter Redirect URI."},
                {jsonWebToken1, true, false, true, true, "Valid Request Object, signed not encrypted.", true},
                {jsonWebToken2, false, false, true, true, "Valid Request Object, not signed not encrypted.", true},
                {jsonWebToken3, false, false, true, false, "InValid Request Object, expired, not signed not " +
                        "encrypted.", true},
                {jsonWebToken4, true, false, true, false, "InValid Request Object, expired, signed not encrypted.",
                        true},
                {jsonWebEncryption1, false, true, true, true, "Valid Request Object, signed and encrypted.", true},
                {jsonWebEncryption2, true, true, true, true, "Valid Request Object, signed and encrypted.", true},
                {jsonWebToken5, true, false, true, true, "Request Object signature verification failed. " +
                        "Invalid signature algorithm.", false}
        };
    }

    @Test(dataProvider = "provideJWT")
    public void testValidateRequestObj(String jwt,
                                       boolean isSigned,
                                       boolean isEncrypted,
                                       boolean validSignature,
                                       boolean validRequestObj,
                                       boolean isFAPITest,
                                       String errorMsg,
                                       boolean validAlgorithm) throws Exception {

        OAuth2Parameters oAuth2Parameters = new OAuth2Parameters();
        oAuth2Parameters.setTenantDomain(SUPER_TENANT_DOMAIN_NAME);
        oAuth2Parameters.setClientId(TEST_CLIENT_ID_1);
        oAuth2Parameters.setRedirectURI(TestConstants.CALLBACK);

        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getServerURL(anyString(), anyBoolean(), anyBoolean())).thenReturn("some-server-url");
        when(IdentityUtil.getPropertyAsList(TestConstants.FAPI_SIGNATURE_ALG_CONFIGURATION))
                .thenReturn(Arrays.asList(JWSAlgorithm.PS256.getName(), JWSAlgorithm.ES256.getName(),
                        JWSAlgorithm.RS256.getName()));

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId(anyString())).thenReturn(-1234);

        IdentityEventService eventServiceMock = mock(IdentityEventService.class);
        mockStatic(CentralLogMgtServiceComponentHolder.class);
        when(CentralLogMgtServiceComponentHolder.getInstance()).thenReturn(centralLogMgtServiceComponentHolderMock);
        when(centralLogMgtServiceComponentHolderMock.getIdentityEventService()).thenReturn(eventServiceMock);
        PowerMockito.doNothing().when(eventServiceMock).handleEvent(any());

        OAuthServerConfiguration oauthServerConfigurationMock = mock(OAuthServerConfiguration.class);
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oauthServerConfigurationMock);

        rsaPrivateKey = (RSAPrivateKey) wso2KeyStore.getKey("wso2carbon", "wso2carbon".toCharArray());
        mockStatic(OAuth2Util.class);
        when(OAuth2Util.getTenantId(SUPER_TENANT_DOMAIN_NAME)).thenReturn(SUPER_TENANT_ID);
        when((OAuth2Util.getPrivateKey(anyString(), anyInt()))).thenReturn(rsaPrivateKey);

        // Mock OAuth2Util returning public cert of the service provider
        when(OAuth2Util.getX509CertOfOAuthApp(TEST_CLIENT_ID_1, SUPER_TENANT_DOMAIN_NAME))
                .thenReturn(clientKeyStore.getCertificate(CLIENT_PUBLIC_CERT_ALIAS));
        when(OAuth2Util.isFapiConformantApp(anyString())).thenReturn(isFAPITest);
        when(OAuth2Util.getServiceProvider(anyString())).thenReturn(new ServiceProvider());

        RequestObjectValidatorImpl requestObjectValidator = PowerMockito.spy(new RequestObjectValidatorImpl());
        doReturn(true).when(requestObjectValidator, "isValidNbfExp", any());
        RequestParamRequestObjectBuilder requestParamRequestObjectBuilder = new RequestParamRequestObjectBuilder();
        when((oauthServerConfigurationMock.getRequestObjectValidator())).thenReturn(requestObjectValidator);

        mockIdentityProviderManager();
        PowerMockito.mockStatic(IdentityApplicationManagementUtil.class);
        FederatedAuthenticatorConfig config = new FederatedAuthenticatorConfig();
        when(IdentityApplicationManagementUtil.getFederatedAuthenticator(any(), any())).thenReturn(config);
        Property property = new Property();
        property.setValue(SOME_SERVER_URL);
        when(IdentityApplicationManagementUtil.getProperty(config.getProperties(), "IdPEntityId"))
                .thenReturn(property);
        OAuthAppDO appDO = spy(new OAuthAppDO());
        appDO.setRequestObjectSignatureAlgorithm("RS256");
        when(OAuth2Util.getAppInformationByClientId(anyString(), anyString())).thenReturn(appDO);

        RequestObject requestObject = requestParamRequestObjectBuilder.buildRequestObject(jwt, oAuth2Parameters);

        Assert.assertEquals(requestParamRequestObjectBuilder.isEncrypted(jwt), isEncrypted,
                "Payload is encrypted:" + isEncrypted);
        Assert.assertEquals(requestObjectValidator.isSigned(requestObject), isSigned,
                "Request object isSigned: " + isSigned);

        if (isSigned) {
            boolean isValidSignature;
            try {
                isValidSignature = requestObjectValidator.validateSignature(requestObject, oAuth2Parameters);
            } catch (Exception e) {
                isValidSignature = false;
            }
            Assert.assertEquals(isValidSignature, validSignature,
                    errorMsg + "Request Object Signature Validation failed.");
        }
        if (isSigned && !validAlgorithm) {
            Assert.assertEquals(requestObjectValidator.validateSignature(requestObject, oAuth2Parameters),
                    validSignature, errorMsg);
        }

        boolean validObject;
        try {
            validObject = requestObjectValidator.validateRequestObject(requestObject, oAuth2Parameters);
        } catch (Exception e) {
            validObject = false;
        }
        Assert.assertEquals(validObject, validRequestObj, errorMsg);
    }

    private void mockIdentityProviderManager() throws Exception {

        IdentityProvider idp = new IdentityProvider();
        idp.setIdentityProviderName("LOCAL");
        idp.setEnable(true);

        PowerMockito.mockStatic(IdentityProviderManager.class);
        IdentityProviderManager identityProviderManager = mock(IdentityProviderManager.class);
        when(IdentityProviderManager.getInstance()).thenReturn(identityProviderManager);
        when(identityProviderManager.getResidentIdP(anyString())).thenReturn(idp);
    }

    @DataProvider(name = "nbfExpDataProvider")
    public Object[][] getNbfExpClaims() {
        long currentTimeMillis = System.currentTimeMillis();
        Date timeInLastHour = new Date(currentTimeMillis - TimeUnit.MINUTES.toMillis(30));
        Date timeInNextHour = new Date(currentTimeMillis + TimeUnit.MINUTES.toMillis(30));

        return new Object[][] {
                {new Date(currentTimeMillis - TimeUnit.MINUTES.toMillis(70)), timeInNextHour, false,
                        "Request Object nbf claim is too old."},
                {timeInLastHour, timeInNextHour, true, null},
                {new Date(currentTimeMillis + TimeUnit.MINUTES.toMillis(10)), timeInNextHour, false,
                        "Request Object is not valid yet."},
                {null, timeInNextHour, false, "Request Object does not contain Not Before Time."},
                {timeInLastHour, new Date(timeInLastHour.getTime() + TimeUnit.MINUTES.toMillis(50)), true,
                        null},
                { timeInLastHour, new Date(timeInLastHour.getTime() + TimeUnit.MINUTES.toMillis(65)), false,
                        "Request Object expiry time is too far in the future than not before time."},
                { timeInLastHour, null, false, "Request Object does not contain Expiration Time."},
        };
    }

    @Test(dataProvider = "nbfExpDataProvider")
    public void testNbfExpClaims(Date nbfTime, Date expTime, boolean shouldPass, String errorMsg) throws Exception {

        RequestObjectValidatorImpl requestObjectValidator = new RequestObjectValidatorImpl();
        RequestObject requestObject = mock(RequestObject.class);

        JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
        jwtClaimsSetBuilder.notBeforeTime(nbfTime);
        jwtClaimsSetBuilder.expirationTime(expTime);
        when(requestObject.getClaimsSet()).thenReturn(jwtClaimsSetBuilder.build());
        OAuthServerConfiguration oauthServerConfigurationMock = mock(OAuthServerConfiguration.class);
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oauthServerConfigurationMock);
        when(oauthServerConfigurationMock.getTimeStampSkewInSeconds()).thenReturn(0L);
        mockStatic(LoggerUtils.class);
        when(LoggerUtils.isDiagnosticLogsEnabled()).thenReturn(false);
        if (shouldPass) {
            requestObjectValidator.isValidNbfExp(requestObject);
        } else {
            try {
                requestObjectValidator.isValidNbfExp(requestObject);
                Assert.fail("Request validation should have failed");
            } catch (RequestObjectException e) {
                Assert.assertEquals(e.getMessage(), errorMsg, "Invalid error message received");
            }
        }

    }

}
