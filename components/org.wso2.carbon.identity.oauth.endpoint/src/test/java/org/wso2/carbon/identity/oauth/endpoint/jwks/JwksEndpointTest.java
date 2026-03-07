/*
 * Copyright (c) 2017-2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth.endpoint.jwks;

import com.nimbusds.jose.JWSAlgorithm;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.stubbing.Answer;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.annotations.AfterTest;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.core.IdentityKeyStoreResolver;
import org.wso2.carbon.identity.core.util.IdentityKeyStoreResolverConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.keyidprovider.DefaultKeyIDProviderImpl;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.utils.CarbonUtils;

import java.io.FileInputStream;
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;
import static org.wso2.carbon.base.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
import static org.wso2.carbon.identity.oauth.endpoint.jwks.JwksEndpoint.JWKS_IS_THUMBPRINT_HEXIFY_REQUIRED;
import static org.wso2.carbon.identity.oauth.endpoint.jwks.JwksEndpoint.JWKS_IS_X5T_REQUIRED;

@Listeners(MockitoTestNGListener.class)
public class JwksEndpointTest {

    @Mock
    ServerConfiguration serverConfiguration;

    @Mock
    OAuthServerConfiguration mockOAuthServerConfiguration;

    @Mock
    TokenPersistenceProcessor tokenPersistenceProcessor;

    private static final String CERT_THUMB_PRINT = "generatedCertThrumbPrint";
    private static final String ALG = "RS256";
    private static final String USE = "sig";
    private static final JSONArray X5C_ARRAY = new JSONArray();
    private static final JSONArray X5T_ARRAY = new JSONArray();
    private static final String ENABLE_X5C_IN_RESPONSE = "JWTValidatorConfigs.JWKSEndpoint.EnableX5CInResponse";
    private JwksEndpoint jwksEndpoint;
    private Object identityUtilObj;

    private MockedStatic<IdentityKeyStoreResolver> identityKeyStoreResolverMockedStatic;
    private IdentityKeyStoreResolver identityKeyStoreResolver;

    @AfterTest
    public void tearDown() {
        if (identityKeyStoreResolverMockedStatic != null) {
            identityKeyStoreResolverMockedStatic.close();
        }
    }

    @BeforeTest
    public void setUp() throws Exception {

        System.setProperty(
                CarbonBaseConstants.CARBON_HOME,
                Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString()
                          );
        jwksEndpoint = new JwksEndpoint();

        Class<?> clazz = IdentityUtil.class;
        identityUtilObj = clazz.newInstance();
        OAuth2ServiceComponentHolder.setKeyIDProvider(new DefaultKeyIDProviderImpl());

        X5C_ARRAY.put("MIIDdzCCAl+gAwIBAgIEdWyfgTANBgkqhkiG9w0BAQsFADBsMRAwDgYDVQQGEwdVbmtub3duMRAwDgYDVQQIEwdVbmtub3" +
                "duMRAwDgYDVQQHEwdVbmtub3duMRAwDgYDVQQKEwdVbmtub3duMRAwDgYDVQQLEwdVbmtub3duMRAwDgYDVQQDEwdVbmtub3duMB" +
                "4XDTE3MTAxNzEwMTIzN1oXDTE4MDExNTEwMTIzN1owbDEQMA4GA1UEBhMHVW5rbm93bjEQMA4GA1UECBMHVW5rbm93bjEQMA4GA1" +
                "UEBxMHVW5rbm93bjEQMA4GA1UEChMHVW5rbm93bjEQMA4GA1UECxMHVW5rbm93bjEQMA4GA1UEAxMHVW5rbm93bjCCASIwDQYJKo" +
                "ZIhvcNAQEBBQADggEPADCCAQoCggEBAJo+aKKahtqFCIZ2xoJoqXLZ7fXg47xpcNT/RZEu3Fbn0jnK1CbjhuAlzs/Iy9WmlFCROt" +
                "4UuZd6x23se9AwKJ/YqDKKUE24ofC5SG+aFWooNfXBN9l0BDNJxrml1KeGSzGoJ7inGW0JFHt3QCu1lOtpmK4hGWBnF3G8wsL0eu" +
                "1nEyO9GBzTSafcnXGhb09LyY9ABSj5ycM7ZIGO6o/afqGO+onVTkNyufsPfNR3+Bc2rqS290kDPhWrIUenN2QwC9cHjCe0zs5zbR" +
                "wSWWOQJ1ubr5WIP0BfeuafxdcxUjDMRYHLIRqiWALUWFFV3KkAdnFguggHfdHP7rrfKg6pDokCAwEAAaMhMB8wHQYDVR0OBBYEFN" +
                "DI9T3betMAjiEAH2NIwB0r2inLMA0GCSqGSIb3DQEBCwUAA4IBAQA3yJEkKywyQ2z4VyEH3aZ4ouEpkk4YgvW2qxwHbono7ZhmEP" +
                "w4rlR1C7ekRbwxpYpO8OY4scKsRWvb7ogX1MyTefLcpwxSMFqW4hVZbY69txdac8PmeQZOCWxGql0x4SezX0p+zhK+YEG6eLtvPO" +
                "b1LmDckXNLGawrkUbaKzg0pVYVF+z3M20HcehfHILlfGGYim+qoo7K47guTrrulUnuLVDcJU4gWjX1zb7RzGLKs1s/JBYXGKfCzQ" +
                "qR6fWiMn1IY5E5kfPa45xh3KndTlYP6jjpjR89Afvipv6Pus0LKk7fWotvDKM5L6j5ui/sowFe2k4/Q0Rfcskm3yf7IOZm");
        X5C_ARRAY.put("MIIDSTCCAjGgAwIBAgIEAoLQ/TANBgkqhkiG9w0BAQsFADBVMQswCQYDVQQGEwJVUzELMAkGA1UECBMCQ0ExFjAUBgNVBA" +
                "cTDU1vdW50YWluIFZpZXcxDTALBgNVBAoTBFdTTzIxEjAQBgNVBAMTCWxvY2FsaG9zdDAeFw0xNzA3MTkwNjUyNTFaFw0yNzA3MT" +
                "cwNjUyNTFaMFUxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UEBxMNTW91bnRhaW4gVmlldzENMAsGA1UEChMEV1NPMj" +
                "ESMBAGA1UEAxMJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAluZFdW1ynitztkWLC6xKegbRWxky+5" +
                "P0p4ShYEOkHs30QI2VCuR6Qo4Bz5rTgLBrky03W1GAVrZxuvKRGj9V9+PmjdGtau4CTXu9pLLcqnruaczoSdvBYA3lS9a7zgFU0+" +
                "s6kMl2EhB+rk7gXluEep7lIOenzfl2f6IoTKa2fVgVd3YKiSGsyL4tztS70vmmX121qm0sTJdKWP4HxXyqK9neolXI9fYyHOYILV" +
                "NZ69z/73OOVhkh/mvTmWZLM7GM6sApmyLX6OXUp8z0pkY+vT/9+zRxxQs7GurC4/C1nK3rI/0ySUgGEafO1atNjYmlFN+M3tZX6n" +
                "EcA6g94IavyQIDAQABoyEwHzAdBgNVHQ4EFgQUtS8kIYxQ8UVvVrZSdgyide9OHxUwDQYJKoZIhvcNAQELBQADggEBABfk5mqsVU" +
                "rpFCYTZZhOxTRRpGXqoW1G05bOxHxs42Paxw8rAJ06Pty9jqM1CgRPpqvZa2lPQBQqZrHkdDE06q4NG0DqMH8NT+tNkXBe9YTre3" +
                "EJCSfsvswtLVDZ7GDvTHKojJjQvdVCzRj6XH5Truwefb4BJz9APtnlyJIvjHk1hdozqyOniVZd0QOxLAbcdt946chNdQvCm6aUOp" +
                "utp8Xogr0KBnEy3U8es2cAfNZaEkPU8Va5bU6Xjny8zGQnXCXxPKp7sMpgO93nPBt/liX1qfyXM7xEotWoxmm6HZx8oWQ8U5aiXj" +
                "Z5RKDWCCq4ZuXl6wVsUz1iE61suO5yWi8=");
        X5T_ARRAY.put("vgeji34kzLU_6u8pLs985j8kPBRFtAYnZi_-yQdktYU");
        X5T_ARRAY.put("UPDtpYmK86EVwsUIGUlW5-EU_iNHQ-nSL3Ca58uAG70");
        X5T_ARRAY.put("YmUwN2EzOGI3ZTI0Y2NiNTNmZWFlZjI5MmVjZjdjZTYzZjI0M2MxNDQ1YjQwNjI3NjYyZmZlYzkwNzY0YjU4NQ");

        X5T_ARRAY.put("Wf7dZ0u8qv1n4N2Jb1y1A3Zk3lE");
        X5T_ARRAY.put("59fedd674bbcaafd67e0dd896f5cb5037664de51");

        mockKeystores();
    }

    @DataProvider(name = "provideTenantDomain")
    public Object[][] provideTenantDomain() {

        return new Object[][]{
                {null, MultitenantConstants.SUPER_TENANT_ID},
                {"", MultitenantConstants.SUPER_TENANT_ID},
                {"foo.com", 1},
                {"invalid.com", -1},
        };
    }

    @Test(dataProvider = "provideTenantDomain")
    public void testJwks(String tenantDomain, int tenantId) throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);
             MockedStatic<CarbonUtils> carbonUtils = mockStatic(CarbonUtils.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<FrameworkUtils> frameworkUtils = mockStatic(FrameworkUtils.class)) {

            mockOAuthServerConfiguration(oAuthServerConfiguration);

            // When the OAuth2Util is mocked, OAuthServerConfiguration instance should be available.
            try (MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class);
                 MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {

                carbonUtils.when(CarbonUtils::getServerConfiguration).thenReturn(serverConfiguration);

                ThreadLocal<Map<String, Object>> threadLocalProperties = new ThreadLocal() {
                    protected Map<String, Object> initialValue() {

                        return new HashMap();
                    }
                };

                threadLocalProperties.get().put(OAuthConstants.TENANT_NAME_FROM_CONTEXT, tenantDomain);

                Field threadLocalPropertiesField = identityUtilObj.getClass().getDeclaredField("threadLocalProperties");

                threadLocalPropertiesField.setAccessible(true);

                // Use Unsafe to modify static final fields in Java 12+
                Field unsafeField = sun.misc.Unsafe.class.getDeclaredField("theUnsafe");
                unsafeField.setAccessible(true);
                sun.misc.Unsafe unsafe = (sun.misc.Unsafe) unsafeField.get(null);

                Object fieldBase = unsafe.staticFieldBase(threadLocalPropertiesField);
                long fieldOffset = unsafe.staticFieldOffset(threadLocalPropertiesField);
                unsafe.putObject(fieldBase, fieldOffset, threadLocalProperties);

                identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString())).thenReturn(tenantId);

                frameworkUtils.when(() -> FrameworkUtils.startTenantFlow("foo.com"))
                        .thenAnswer((Answer<Void>) invocation -> null);
                frameworkUtils.when(FrameworkUtils::endTenantFlow).thenAnswer((Answer<Void>) invocation -> null);

                if (tenantDomain == null) {
                    oAuth2Util.when(() -> OAuth2Util.getKID(any(), any(), anyString()))
                            .thenThrow(new IdentityOAuth2Exception("error"));
                } else {
                    oAuth2Util.when(() -> OAuth2Util.getKID(any(), any(), anyString())).thenReturn(CERT_THUMB_PRINT);
                }
                oAuth2Util.when(() -> OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm("SHA256withRSA"))
                        .thenReturn(JWSAlgorithm.RS256);
                oAuth2Util.when(() -> OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm("SHA512withRSA"))
                        .thenReturn(JWSAlgorithm.RS512);
                oAuth2Util.when(() -> OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm("SHA384withRSA"))
                        .thenReturn(JWSAlgorithm.RS384);
                oAuth2Util.when(() -> OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm("EdDSA"))
                        .thenReturn(JWSAlgorithm.EdDSA);
                if ("foo.com".equals(tenantDomain)) {
                    oAuth2Util.when(() -> OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm("SHA512withRSA"))
                            .thenReturn(JWSAlgorithm.RS256);
                }
                oAuth2Util.when(() -> OAuth2Util.getThumbPrint(any(), anyString()))
                        .thenReturn("YmUwN2EzOGI3ZTI0Y2NiNTNmZWFlZjI5Mm" +
                                "VjZjdjZTYzZjI0M2MxNDQ1YjQwNjI3NjYyZmZlYzkwNzY0YjU4NQ");

                identityUtil.when(() -> IdentityUtil.getProperty(ENABLE_X5C_IN_RESPONSE)).thenReturn("true");

                String result = jwksEndpoint.jwks();

                try {
                    JSONObject jwksJson = new JSONObject(result);
                    JSONArray objectArray = jwksJson.getJSONArray("keys");
                    JSONObject keyObject = objectArray.getJSONObject(0);
                    assertEquals(keyObject.get("kid"), CERT_THUMB_PRINT, "Incorrect kid value");
                    assertEquals(keyObject.get("alg"), ALG, "Incorrect alg value");
                    assertEquals(keyObject.get("use"), USE, "Incorrect use value");
                    assertEquals(keyObject.get("kty"), "RSA", "Incorrect kty value");
                    if ("foo.com".equals(tenantDomain)) {
                        assertEquals(objectArray.length(), 2, "Incorrect no of keysets");
                        assertEquals(((JSONArray) keyObject.get("x5c")).get(0), X5C_ARRAY.get(0),
                                "Incorrect x5c value");
                        assertEquals(keyObject.get("x5t#S256"), X5T_ARRAY.get(0), "Incorrect x5t#S256 value");
                    } else {
                        assertEquals(objectArray.length(), 3, "Incorrect no of keysets");
                        assertEquals(((JSONArray) keyObject.get("x5c")).get(0), X5C_ARRAY.get(1),
                                "Incorrect x5c value");
                        assertEquals(keyObject.get("x5t#S256"), X5T_ARRAY.get(1), "Incorrect x5t#S256 value");
                    }
                    String base64UrlEncodedString = (String) keyObject.get("x5t#S256");
                    byte[] decodedBytes = Base64.getUrlDecoder().decode(base64UrlEncodedString);
                    assertEquals(decodedBytes.length, 32, "Incorrect x5t#S256 size");
                } catch (JSONException e) {
                    if ("invalid.com".equals(tenantDomain)) {
                        // This is expected. We don't validate for invalid tenants.
                        assertTrue(true);
                    } else if (tenantDomain == null) {
                        assertTrue(result.contains("Error while generating the keyset for"),
                                "Error message for thrown exception is not found");
                    } else {
                        fail("Unexpected exception: " + e.getMessage());
                    }
                }

                threadLocalProperties.get().remove(OAuthConstants.TENANT_NAME_FROM_CONTEXT);
            }
        }
    }

    @DataProvider(name = "jwksHexifyAndX5tEnabledProvider")
    public Object[][] jwksHexifyAndX5tEnabledProvider() {

        return new Object[][]{
                {false, false},
                {false, true},
                {true, true}
        };
    }

    @Test(dataProvider = "jwksHexifyAndX5tEnabledProvider")
    public void testJwks(boolean hexifyRequired, boolean enableX5tInJWKS) throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);
             MockedStatic<CarbonUtils> carbonUtils = mockStatic(CarbonUtils.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class)) {

            mockOAuthServerConfiguration(oAuthServerConfiguration);

            // When the OAuth2Util is mocked, OAuthServerConfiguration instance should be available.
            try (MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class);
                 MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {

                carbonUtils.when(CarbonUtils::getServerConfiguration).thenReturn(serverConfiguration);

                identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString())).thenReturn(-1234);

                oAuth2Util.when(() -> OAuth2Util.getKID(any(), any(), anyString())).thenReturn(CERT_THUMB_PRINT);

                oAuth2Util.when(() -> OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm("SHA256withRSA"))
                        .thenReturn(JWSAlgorithm.RS256);
                oAuth2Util.when(() -> OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm("SHA512withRSA"))
                        .thenReturn(JWSAlgorithm.RS512);
                oAuth2Util.when(() -> OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm("SHA384withRSA"))
                        .thenReturn(JWSAlgorithm.RS384);

                oAuth2Util.when(() -> OAuth2Util.getThumbPrint(any(), anyString()))
                        .thenReturn("YmUwN2EzOGI3ZTI0Y2NiNTNmZWFlZjI5Mm" +
                                "VjZjdjZTYzZjI0M2MxNDQ1YjQwNjI3NjYyZmZlYzkwNzY0YjU4NQ");

                oAuth2Util.when(() -> OAuth2Util.getThumbPrintWithPrevAlgorithm(any(), eq(false)))
                        .thenReturn("Wf7dZ0u8qv1n4N2Jb1y1A3Zk3lE");
                oAuth2Util.when(() -> OAuth2Util.getThumbPrintWithPrevAlgorithm(any(), eq(true)))
                        .thenReturn("59fedd674bbcaafd67e0dd896f5cb5037664de51");

                identityUtil.when(() -> IdentityUtil.getProperty(ENABLE_X5C_IN_RESPONSE)).thenReturn("true");
                identityUtil.when(() -> IdentityUtil.getProperty(JWKS_IS_THUMBPRINT_HEXIFY_REQUIRED))
                        .thenReturn(String.valueOf(hexifyRequired));
                identityUtil.when(() -> IdentityUtil.getProperty(JWKS_IS_X5T_REQUIRED))
                        .thenReturn(String.valueOf(enableX5tInJWKS));

                String result = jwksEndpoint.jwks();

                try {
                    JSONObject jwksJson = new JSONObject(result);
                    JSONArray objectArray = jwksJson.getJSONArray("keys");
                    JSONObject keyObject = objectArray.getJSONObject(0);
                    assertEquals(keyObject.get("kid"), CERT_THUMB_PRINT, "Incorrect kid value");
                    assertEquals(keyObject.get("alg"), ALG, "Incorrect alg value");
                    assertEquals(keyObject.get("use"), USE, "Incorrect use value");
                    assertEquals(keyObject.get("kty"), "RSA", "Incorrect kty value");
                    assertEquals(objectArray.length(), 3, "Incorrect no of keysets");
                    assertEquals(((JSONArray) keyObject.get("x5c")).get(0), X5C_ARRAY.get(1),
                            "Incorrect x5c value");
                    if (hexifyRequired) {
                        assertEquals(keyObject.get("x5t#S256"), X5T_ARRAY.get(2), "Incorrect x5t#S256 value");
                    } else {
                        assertEquals(keyObject.get("x5t#S256"), X5T_ARRAY.get(1), "Incorrect x5t#S256 value");
                    }
                    if (enableX5tInJWKS) {
                        if (hexifyRequired) {
                            assertEquals(keyObject.get("x5t"), X5T_ARRAY.get(4), "Incorrect x5t value");
                        } else {
                            assertEquals(keyObject.get("x5t"), X5T_ARRAY.get(3), "Incorrect x5t value");
                        }
                    }
                    String base64UrlEncodedString = (String) keyObject.get("x5t#S256");
                    byte[] decodedBytes = Base64.getUrlDecoder().decode(base64UrlEncodedString);
                    if (hexifyRequired) {
                        assertEquals(decodedBytes.length, 64, "Incorrect x5t#S256 size");
                    } else {
                        assertEquals(decodedBytes.length, 32, "Incorrect x5t#S256 size");
                    }
                } catch (JSONException e) {
                    fail("Unexpected exception: " + e.getMessage());
                }
            }
        }
    }

    private void mockOAuthServerConfiguration(MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration)
            throws Exception {

        oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance).thenReturn(mockOAuthServerConfiguration);
        lenient().when(mockOAuthServerConfiguration.getPersistenceProcessor()).thenReturn(tokenPersistenceProcessor);
        lenient().when(mockOAuthServerConfiguration.getIdTokenSignatureAlgorithm()).thenReturn("SHA512withRSA");
        lenient().when(mockOAuthServerConfiguration.getSignatureAlgorithm()).thenReturn("SHA256withRSA");
        lenient().when(mockOAuthServerConfiguration.getUserInfoJWTSignatureAlgorithm()).thenReturn("SHA384withRSA");
    }

    /**
     * Builds an in-memory KeyStore containing a self-signed certificate generated from the given key pair
     * using BouncyCastle.
     */
    private KeyStore buildKeyStoreWithKeyPair(KeyPair keyPair, String alias, String keystorePassword)
            throws Exception {

        org.bouncycastle.asn1.x500.X500Name subject =
                new org.bouncycastle.asn1.x500.X500Name("CN=Test");
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 365L * 24 * 60 * 60 * 1000);

        org.bouncycastle.cert.X509v3CertificateBuilder certBuilder =
                new org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(
                        subject, serial, notBefore, notAfter, subject, keyPair.getPublic());

        String sigAlg;
        if (keyPair.getPublic().getAlgorithm().equals("EC")) {
            sigAlg = "SHA256withECDSA";
        } else if (keyPair.getPublic().getAlgorithm().equals("EdDSA") ||
                keyPair.getPublic().getAlgorithm().equals("Ed25519")) {
            sigAlg = "Ed25519";
        } else {
            sigAlg = "SHA256withRSA";
        }

        org.bouncycastle.operator.ContentSigner signer =
                new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder(sigAlg)
                        .build(keyPair.getPrivate());

        X509Certificate cert = new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter()
                .getCertificate(certBuilder.build(signer));

        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(null, keystorePassword.toCharArray());
        ks.setKeyEntry(alias, keyPair.getPrivate(), keystorePassword.toCharArray(),
                new Certificate[]{cert});
        return ks;
    }

    @Test
    public void testJwksWithECKey() throws Exception {

        // Generate EC P-256 key pair
        KeyPairGenerator ecKpg = KeyPairGenerator.getInstance("EC");
        ecKpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair ecKeyPair = ecKpg.generateKeyPair();
        KeyStore ecKeyStore = buildKeyStoreWithKeyPair(ecKeyPair, "eckey", "ecpass");

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);
             MockedStatic<CarbonUtils> carbonUtils = mockStatic(CarbonUtils.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class)) {

            mockOAuthServerConfiguration(oAuthServerConfiguration);

            try (MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class);
                 MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {

                carbonUtils.when(CarbonUtils::getServerConfiguration).thenReturn(serverConfiguration);
                identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString()))
                        .thenReturn(MultitenantConstants.SUPER_TENANT_ID);

                // Use the EC keystore
                IdentityKeyStoreResolver mockResolver = mock(IdentityKeyStoreResolver.class);
                when(mockResolver.getKeyStore(anyString(), any())).thenReturn(ecKeyStore);
                identityKeyStoreResolverMockedStatic.when(IdentityKeyStoreResolver::getInstance)
                        .thenReturn(mockResolver);

                oAuth2Util.when(() -> OAuth2Util.getKID(any(), any(), anyString())).thenReturn(CERT_THUMB_PRINT);
                oAuth2Util.when(() -> OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm(anyString()))
                        .thenReturn(JWSAlgorithm.RS256);
                oAuth2Util.when(() -> OAuth2Util.getThumbPrint(any(), anyString()))
                        .thenReturn("YmUwN2EzOGI3ZTI0Y2NiNTNmZWFlZjI5Mm" +
                                "VjZjdjZTYzZjI0M2MxNDQ1YjQwNjI3NjYyZmZlYzkwNzY0YjU4NQ");

                identityUtil.when(() -> IdentityUtil.getProperty(ENABLE_X5C_IN_RESPONSE)).thenReturn("true");

                String result = jwksEndpoint.jwks();
                JSONObject jwksJson = new JSONObject(result);
                JSONArray objectArray = jwksJson.getJSONArray("keys");
                assertEquals(objectArray.length(), 1, "Should have 1 EC key");
                JSONObject keyObject = objectArray.getJSONObject(0);
                assertEquals(keyObject.get("kty"), "EC", "Key type should be EC");
                assertEquals(keyObject.get("alg"), "ES256", "Algorithm should be ES256");
                assertEquals(keyObject.get("use"), USE, "Use should be sig");
            }
        } finally {
            identityKeyStoreResolverMockedStatic.when(IdentityKeyStoreResolver::getInstance)
                    .thenReturn(identityKeyStoreResolver);
        }
    }

    @Test
    public void testJwksWithEdDSAKey() throws Exception {

        // Generate EdDSA (Ed25519) key pair
        KeyPairGenerator edKpg = KeyPairGenerator.getInstance("EdDSA");
        KeyPair edKeyPair = edKpg.generateKeyPair();
        KeyStore edKeyStore = buildKeyStoreWithKeyPair(edKeyPair, "edkey", "edpass");

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);
             MockedStatic<CarbonUtils> carbonUtils = mockStatic(CarbonUtils.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class)) {

            mockOAuthServerConfiguration(oAuthServerConfiguration);

            try (MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class);
                 MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {

                carbonUtils.when(CarbonUtils::getServerConfiguration).thenReturn(serverConfiguration);
                identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString()))
                        .thenReturn(MultitenantConstants.SUPER_TENANT_ID);

                IdentityKeyStoreResolver mockResolver = mock(IdentityKeyStoreResolver.class);
                when(mockResolver.getKeyStore(anyString(), any())).thenReturn(edKeyStore);
                identityKeyStoreResolverMockedStatic.when(IdentityKeyStoreResolver::getInstance)
                        .thenReturn(mockResolver);

                oAuth2Util.when(() -> OAuth2Util.getKID(any(), any(), anyString())).thenReturn(CERT_THUMB_PRINT);
                oAuth2Util.when(() -> OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm(anyString()))
                        .thenReturn(JWSAlgorithm.EdDSA);
                oAuth2Util.when(() -> OAuth2Util.getThumbPrint(any(), anyString()))
                        .thenReturn("YmUwN2EzOGI3ZTI0Y2NiNTNmZWFlZjI5Mm" +
                                "VjZjdjZTYzZjI0M2MxNDQ1YjQwNjI3NjYyZmZlYzkwNzY0YjU4NQ");

                identityUtil.when(() -> IdentityUtil.getProperty(ENABLE_X5C_IN_RESPONSE)).thenReturn("true");

                String result = jwksEndpoint.jwks();
                JSONObject jwksJson = new JSONObject(result);
                JSONArray objectArray = jwksJson.getJSONArray("keys");
                assertEquals(objectArray.length(), 1, "Should have 1 EdDSA key");
                JSONObject keyObject = objectArray.getJSONObject(0);
                assertEquals(keyObject.get("kty"), "OKP", "Key type should be OKP");
                assertEquals(keyObject.get("alg"), "EdDSA", "Algorithm should be EdDSA");
            }
        } finally {
            identityKeyStoreResolverMockedStatic.when(IdentityKeyStoreResolver::getInstance)
                    .thenReturn(identityKeyStoreResolver);
        }
    }

    @Test
    public void testJwksWithEdDSAKeyAndX5tEnabled() throws Exception {

        KeyPairGenerator edKpg = KeyPairGenerator.getInstance("EdDSA");
        KeyPair edKeyPair = edKpg.generateKeyPair();
        KeyStore edKeyStore = buildKeyStoreWithKeyPair(edKeyPair, "edkey2", "edpass2");

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);
             MockedStatic<CarbonUtils> carbonUtils = mockStatic(CarbonUtils.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class)) {

            mockOAuthServerConfiguration(oAuthServerConfiguration);

            try (MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class);
                 MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {

                carbonUtils.when(CarbonUtils::getServerConfiguration).thenReturn(serverConfiguration);
                identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString()))
                        .thenReturn(MultitenantConstants.SUPER_TENANT_ID);

                IdentityKeyStoreResolver mockResolver = mock(IdentityKeyStoreResolver.class);
                when(mockResolver.getKeyStore(anyString(), any())).thenReturn(edKeyStore);
                identityKeyStoreResolverMockedStatic.when(IdentityKeyStoreResolver::getInstance)
                        .thenReturn(mockResolver);

                oAuth2Util.when(() -> OAuth2Util.getKID(any(), any(), anyString())).thenReturn(CERT_THUMB_PRINT);
                oAuth2Util.when(() -> OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm(anyString()))
                        .thenReturn(JWSAlgorithm.EdDSA);
                oAuth2Util.when(() -> OAuth2Util.getThumbPrint(any(), anyString()))
                        .thenReturn("YmUwN2EzOGI3ZTI0Y2NiNTNmZWFlZjI5Mm" +
                                "VjZjdjZTYzZjI0M2MxNDQ1YjQwNjI3NjYyZmZlYzkwNzY0YjU4NQ");
                oAuth2Util.when(() -> OAuth2Util.getThumbPrintWithPrevAlgorithm(any(), eq(false)))
                        .thenReturn("Wf7dZ0u8qv1n4N2Jb1y1A3Zk3lE");
                oAuth2Util.when(() -> OAuth2Util.getThumbPrintWithPrevAlgorithm(any(), eq(true)))
                        .thenReturn("59fedd674bbcaafd67e0dd896f5cb5037664de51");

                identityUtil.when(() -> IdentityUtil.getProperty(ENABLE_X5C_IN_RESPONSE)).thenReturn("true");
                identityUtil.when(() -> IdentityUtil.getProperty(JWKS_IS_THUMBPRINT_HEXIFY_REQUIRED))
                        .thenReturn("true");
                identityUtil.when(() -> IdentityUtil.getProperty(JWKS_IS_X5T_REQUIRED)).thenReturn("true");

                String result = jwksEndpoint.jwks();
                JSONObject jwksJson = new JSONObject(result);
                JSONArray objectArray = jwksJson.getJSONArray("keys");
                assertEquals(objectArray.length(), 1);
                JSONObject keyObject = objectArray.getJSONObject(0);
                assertEquals(keyObject.get("kty"), "OKP", "Key type should be OKP for EdDSA");
                assertTrue(keyObject.has("x5t"), "x5t should be present when enabled");
            }
        } finally {
            identityKeyStoreResolverMockedStatic.when(IdentityKeyStoreResolver::getInstance)
                    .thenReturn(identityKeyStoreResolver);
        }
    }

    @Test
    public void testJwksWithECKeyAndX5cEnabled() throws Exception {

        KeyPairGenerator ecKpg = KeyPairGenerator.getInstance("EC");
        ecKpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair ecKeyPair = ecKpg.generateKeyPair();
        KeyStore ecKeyStore = buildKeyStoreWithKeyPair(ecKeyPair, "eckey2", "ecpass2");

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);
             MockedStatic<CarbonUtils> carbonUtils = mockStatic(CarbonUtils.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class)) {

            mockOAuthServerConfiguration(oAuthServerConfiguration);

            try (MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class);
                 MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {

                carbonUtils.when(CarbonUtils::getServerConfiguration).thenReturn(serverConfiguration);
                identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString()))
                        .thenReturn(MultitenantConstants.SUPER_TENANT_ID);

                IdentityKeyStoreResolver mockResolver = mock(IdentityKeyStoreResolver.class);
                when(mockResolver.getKeyStore(anyString(), any())).thenReturn(ecKeyStore);
                identityKeyStoreResolverMockedStatic.when(IdentityKeyStoreResolver::getInstance)
                        .thenReturn(mockResolver);

                oAuth2Util.when(() -> OAuth2Util.getKID(any(), any(), anyString())).thenReturn(CERT_THUMB_PRINT);
                oAuth2Util.when(() -> OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm(anyString()))
                        .thenReturn(JWSAlgorithm.RS256);
                oAuth2Util.when(() -> OAuth2Util.getThumbPrint(any(), anyString()))
                        .thenReturn("YmUwN2EzOGI3ZTI0Y2NiNTNmZWFlZjI5Mm" +
                                "VjZjdjZTYzZjI0M2MxNDQ1YjQwNjI3NjYyZmZlYzkwNzY0YjU4NQ");
                oAuth2Util.when(() -> OAuth2Util.getThumbPrintWithPrevAlgorithm(any(), eq(false)))
                        .thenReturn("Wf7dZ0u8qv1n4N2Jb1y1A3Zk3lE");

                identityUtil.when(() -> IdentityUtil.getProperty(ENABLE_X5C_IN_RESPONSE)).thenReturn("true");
                identityUtil.when(() -> IdentityUtil.getProperty(JWKS_IS_X5T_REQUIRED)).thenReturn("true");

                String result = jwksEndpoint.jwks();
                JSONObject jwksJson = new JSONObject(result);
                JSONArray objectArray = jwksJson.getJSONArray("keys");
                assertEquals(objectArray.length(), 1);
                JSONObject keyObject = objectArray.getJSONObject(0);
                assertEquals(keyObject.get("kty"), "EC", "Key type should be EC");
                assertTrue(keyObject.has("x5c"), "x5c should be present when enabled");
                assertTrue(keyObject.has("x5t"), "x5t should be present when enabled");
            }
        } finally {
            identityKeyStoreResolverMockedStatic.when(IdentityKeyStoreResolver::getInstance)
                    .thenReturn(identityKeyStoreResolver);
        }
    }

    @Test
    public void testJwksWithCertificateEncodingExceptionInChain() throws Exception {

        // Create a bad certificate that throws on getEncoded()
        X509Certificate badCert = mock(X509Certificate.class);
        when(badCert.getEncoded()).thenThrow(
                new java.security.cert.CertificateEncodingException("test encoding error"));

        IdentityKeyStoreResolver mockResolver = mock(IdentityKeyStoreResolver.class);
        KeyStore mockKeystore = mock(KeyStore.class);
        when(mockResolver.getKeyStore(anyString(), any())).thenReturn(mockKeystore);
        java.util.Enumeration<String> aliases = java.util.Collections.enumeration(
                java.util.Arrays.asList("badAlias"));
        when(mockKeystore.aliases()).thenReturn(aliases);
        when(mockKeystore.isKeyEntry("badAlias")).thenReturn(true);
        when(mockKeystore.getCertificate("badAlias")).thenReturn(badCert);
        when(mockKeystore.getCertificateChain("badAlias")).thenReturn(new Certificate[]{badCert});

        identityKeyStoreResolverMockedStatic.when(IdentityKeyStoreResolver::getInstance)
                .thenReturn(mockResolver);

        try {
            String result = jwksEndpoint.jwks();
            assertTrue(result.contains("Error while generating the keyset"),
                    "Should return error message for encoding exception");
        } finally {
            identityKeyStoreResolverMockedStatic.when(IdentityKeyStoreResolver::getInstance)
                    .thenReturn(identityKeyStoreResolver);
        }
    }

    private KeyStore getKeyStoreFromFile(String keystoreName, String password) throws Exception {

        Path tenantKeystorePath = Paths.get(System.getProperty(CarbonBaseConstants.CARBON_HOME), "repository",
                "resources", "security", keystoreName);
        FileInputStream file = new FileInputStream(tenantKeystorePath.toString());
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(file, password.toCharArray());
        return keystore;
    }

    private void mockKeystores() throws Exception {

        identityKeyStoreResolver = mock(IdentityKeyStoreResolver.class);
        when(identityKeyStoreResolver.getKeyStore(SUPER_TENANT_DOMAIN_NAME,
                IdentityKeyStoreResolverConstants.InboundProtocol.OAUTH)).thenReturn(
                getKeyStoreFromFile("wso2carbon.jks", "wso2carbon"));
        when(identityKeyStoreResolver.getKeyStore("foo.com",
                IdentityKeyStoreResolverConstants.InboundProtocol.OAUTH)).thenReturn(
                getKeyStoreFromFile("foo-com.jks", "foo.com"));

        identityKeyStoreResolverMockedStatic = mockStatic(IdentityKeyStoreResolver.class);
        identityKeyStoreResolverMockedStatic.when(IdentityKeyStoreResolver::getInstance)
                .thenReturn(identityKeyStoreResolver);
    }

    @Test
    public void testJwksWithCertificateEncodingException() throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);
             MockedStatic<CarbonUtils> carbonUtils = mockStatic(CarbonUtils.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class)) {

            mockOAuthServerConfiguration(oAuthServerConfiguration);
            carbonUtils.when(CarbonUtils::getServerConfiguration).thenReturn(serverConfiguration);
            identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString()))
                    .thenReturn(MultitenantConstants.SUPER_TENANT_ID);

            // Mock keystore to throw exception
            IdentityKeyStoreResolver mockResolver = mock(IdentityKeyStoreResolver.class);
            KeyStore mockKeystore = mock(KeyStore.class);
            when(mockResolver.getKeyStore(anyString(), any())).thenReturn(mockKeystore);
            when(mockKeystore.aliases()).thenThrow(new RuntimeException("Test exception"));

            identityKeyStoreResolverMockedStatic.when(IdentityKeyStoreResolver::getInstance)
                    .thenReturn(mockResolver);

            String result = jwksEndpoint.jwks();
            assertTrue(result.contains("Error while generating the keyset"));
        } finally {
            // Reset static mock to original resolver for subsequent tests
            identityKeyStoreResolverMockedStatic.when(IdentityKeyStoreResolver::getInstance)
                    .thenReturn(identityKeyStoreResolver);
        }
    }

    @Test
    public void testJwksWithNoCertificateChain() throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);
             MockedStatic<CarbonUtils> carbonUtils = mockStatic(CarbonUtils.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class)) {

            mockOAuthServerConfiguration(oAuthServerConfiguration);

            try (MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class);
                 MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {

                carbonUtils.when(CarbonUtils::getServerConfiguration).thenReturn(serverConfiguration);
                identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString()))
                        .thenReturn(MultitenantConstants.SUPER_TENANT_ID);

                oAuth2Util.when(() -> OAuth2Util.getKID(any(), any(), anyString())).thenReturn(CERT_THUMB_PRINT);
                oAuth2Util.when(() -> OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm("SHA256withRSA"))
                        .thenReturn(JWSAlgorithm.RS256);
                oAuth2Util.when(() -> OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm("SHA512withRSA"))
                        .thenReturn(JWSAlgorithm.RS512);
                oAuth2Util.when(() -> OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm("SHA384withRSA"))
                        .thenReturn(JWSAlgorithm.RS384);
                oAuth2Util.when(() -> OAuth2Util.getThumbPrint(any(), anyString()))
                        .thenReturn("YmUwN2EzOGI3ZTI0Y2NiNTNmZWFlZjI5Mm" +
                                "VjZjdjZTYzZjI0M2MxNDQ1YjQwNjI3NjYyZmZlYzkwNzY0YjU4NQ");

                identityUtil.when(() -> IdentityUtil.getProperty(ENABLE_X5C_IN_RESPONSE)).thenReturn("false");

                String result = jwksEndpoint.jwks();
                assertTrue(result.contains("keys"));
            }
        } finally {
            identityKeyStoreResolverMockedStatic.when(IdentityKeyStoreResolver::getInstance)
                    .thenReturn(identityKeyStoreResolver);
        }
    }

    @Test
    public void testJwksWithAddPreviousVersionKIDEnabled() throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);
             MockedStatic<CarbonUtils> carbonUtils = mockStatic(CarbonUtils.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class)) {

            mockOAuthServerConfiguration(oAuthServerConfiguration);

            try (MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class);
                 MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {

                carbonUtils.when(CarbonUtils::getServerConfiguration).thenReturn(serverConfiguration);
                identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString()))
                        .thenReturn(MultitenantConstants.SUPER_TENANT_ID);

                oAuth2Util.when(() -> OAuth2Util.getKID(any(), any(), anyString())).thenReturn(CERT_THUMB_PRINT);
                oAuth2Util.when(() -> OAuth2Util.getPreviousKID(any(), any(), anyString()))
                        .thenReturn("oldKID");
                oAuth2Util.when(() -> OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm("SHA256withRSA"))
                        .thenReturn(JWSAlgorithm.RS256);
                oAuth2Util.when(() -> OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm("SHA512withRSA"))
                        .thenReturn(JWSAlgorithm.RS512);
                oAuth2Util.when(() -> OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm("SHA384withRSA"))
                        .thenReturn(JWSAlgorithm.RS384);
                oAuth2Util.when(() -> OAuth2Util.getThumbPrint(any(), anyString()))
                        .thenReturn("YmUwN2EzOGI3ZTI0Y2NiNTNmZWFlZjI5Mm" +
                                "VjZjdjZTYzZjI0M2MxNDQ1YjQwNjI3NjYyZmZlYzkwNzY0YjU4NQ");
                oAuth2Util.when(() -> OAuth2Util.getThumbPrintWithPrevAlgorithm(any(), eq(false)))
                        .thenReturn("oldThumbprint");
                oAuth2Util.when(() -> OAuth2Util.getThumbPrintWithPrevAlgorithm(any(), eq(true)))
                        .thenReturn("oldThumbprint");

                identityUtil.when(() -> IdentityUtil.getProperty(ENABLE_X5C_IN_RESPONSE)).thenReturn("true");
                identityUtil.when(() -> IdentityUtil.getProperty(
                        "JWTValidatorConfigs.JWKSEndpoint.AddPreviousVersionKID")).thenReturn("true");

                String result = jwksEndpoint.jwks();
                assertTrue(result.contains("keys"));
                JSONObject jwksJson = new JSONObject(result);
                JSONArray objectArray = jwksJson.getJSONArray("keys");
                // Should have more keys due to previous version KID (current keys + previous KID keys)
                assertTrue(objectArray.length() >= 3);
            }
        }
    }

    @Test
    public void testJwksWithSameAlgorithmForAllTokenTypes() throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);
             MockedStatic<CarbonUtils> carbonUtils = mockStatic(CarbonUtils.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class)) {

            // Configure same algorithm for all token types
            oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance)
                    .thenReturn(mockOAuthServerConfiguration);
            lenient().when(mockOAuthServerConfiguration.getPersistenceProcessor())
                    .thenReturn(tokenPersistenceProcessor);
            lenient().when(mockOAuthServerConfiguration.getIdTokenSignatureAlgorithm())
                    .thenReturn("SHA256withRSA");
            lenient().when(mockOAuthServerConfiguration.getSignatureAlgorithm()).thenReturn("SHA256withRSA");
            lenient().when(mockOAuthServerConfiguration.getUserInfoJWTSignatureAlgorithm())
                    .thenReturn("SHA256withRSA");

            try (MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class);
                 MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {

                carbonUtils.when(CarbonUtils::getServerConfiguration).thenReturn(serverConfiguration);
                identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString()))
                        .thenReturn(MultitenantConstants.SUPER_TENANT_ID);

                oAuth2Util.when(() -> OAuth2Util.getKID(any(), any(), anyString())).thenReturn(CERT_THUMB_PRINT);
                oAuth2Util.when(() -> OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm("SHA256withRSA"))
                        .thenReturn(JWSAlgorithm.RS256);
                oAuth2Util.when(() -> OAuth2Util.getThumbPrint(any(), anyString()))
                        .thenReturn("YmUwN2EzOGI3ZTI0Y2NiNTNmZWFlZjI5Mm" +
                                "VjZjdjZTYzZjI0M2MxNDQ1YjQwNjI3NjYyZmZlYzkwNzY0YjU4NQ");

                identityUtil.when(() -> IdentityUtil.getProperty(ENABLE_X5C_IN_RESPONSE)).thenReturn("true");

                String result = jwksEndpoint.jwks();
                JSONObject jwksJson = new JSONObject(result);
                JSONArray objectArray = jwksJson.getJSONArray("keys");
                // Only one algorithm, so 1 key per certificate entry
                assertTrue(objectArray.length() >= 1);
                JSONObject keyObject = objectArray.getJSONObject(0);
                assertEquals(keyObject.get("alg"), "RS256", "Incorrect alg value");
            }
        } finally {
            identityKeyStoreResolverMockedStatic.when(IdentityKeyStoreResolver::getInstance)
                    .thenReturn(identityKeyStoreResolver);
        }
    }

    @Test
    public void testJwksWithEmptyCertificateChain() throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);
             MockedStatic<CarbonUtils> carbonUtils = mockStatic(CarbonUtils.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class)) {

            mockOAuthServerConfiguration(oAuthServerConfiguration);

            try (MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class);
                 MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {

                carbonUtils.when(CarbonUtils::getServerConfiguration).thenReturn(serverConfiguration);
                identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString()))
                        .thenReturn(MultitenantConstants.SUPER_TENANT_ID);

                KeyStore tempKeystore = getKeyStoreFromFile("wso2carbon.jks", "wso2carbon");
                java.security.cert.Certificate mockCert = tempKeystore.getCertificate("wso2carbon");

                IdentityKeyStoreResolver mockResolver = mock(IdentityKeyStoreResolver.class);
                KeyStore mockKeystore = mock(KeyStore.class);
                when(mockResolver.getKeyStore(anyString(), any())).thenReturn(mockKeystore);
                java.util.Enumeration<String> aliases = java.util.Collections.enumeration(
                        java.util.Arrays.asList("testAlias"));
                when(mockKeystore.aliases()).thenReturn(aliases);
                when(mockKeystore.isKeyEntry("testAlias")).thenReturn(true);
                when(mockKeystore.getCertificate("testAlias")).thenReturn(mockCert);
                when(mockKeystore.getCertificateChain("testAlias")).thenReturn(null);

                identityKeyStoreResolverMockedStatic.when(IdentityKeyStoreResolver::getInstance)
                        .thenReturn(mockResolver);

                oAuth2Util.when(() -> OAuth2Util.getKID(any(), any(), anyString())).thenReturn(CERT_THUMB_PRINT);
                oAuth2Util.when(() -> OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm("SHA256withRSA"))
                        .thenReturn(JWSAlgorithm.RS256);
                oAuth2Util.when(() -> OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm("SHA512withRSA"))
                        .thenReturn(JWSAlgorithm.RS512);
                oAuth2Util.when(() -> OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm("SHA384withRSA"))
                        .thenReturn(JWSAlgorithm.RS384);
                oAuth2Util.when(() -> OAuth2Util.getThumbPrint(any(), anyString()))
                        .thenReturn("YmUwN2EzOGI3ZTI0Y2NiNTNmZWFlZjI5Mm" +
                                "VjZjdjZTYzZjI0M2MxNDQ1YjQwNjI3NjYyZmZlYzkwNzY0YjU4NQ");

                identityUtil.when(() -> IdentityUtil.getProperty(ENABLE_X5C_IN_RESPONSE)).thenReturn("true");

                String result = jwksEndpoint.jwks();
                JSONObject jwksJson = new JSONObject(result);
                JSONArray objectArray = jwksJson.getJSONArray("keys");
                assertTrue(objectArray.length() > 0);

                // Verify key doesn't have x5c when chain is null
                JSONObject keyObject = objectArray.getJSONObject(0);
                org.testng.Assert.assertFalse(keyObject.has("x5c"),
                        "x5c should not be present when cert chain is null");
            }
        } finally {
            // Reset static mock to original resolver for subsequent tests
            identityKeyStoreResolverMockedStatic.when(IdentityKeyStoreResolver::getInstance)
                    .thenReturn(identityKeyStoreResolver);
        }
    }

    @Test
    public void testJwksWithEmptyTenantDomainFromContext() throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);
             MockedStatic<CarbonUtils> carbonUtils = mockStatic(CarbonUtils.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class)) {

            mockOAuthServerConfiguration(oAuthServerConfiguration);

            try (MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class);
                 MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {

                carbonUtils.when(CarbonUtils::getServerConfiguration).thenReturn(serverConfiguration);

                ThreadLocal<Map<String, Object>> threadLocalProperties = new ThreadLocal() {
                    protected Map<String, Object> initialValue() {
                        return new HashMap();
                    }
                };

                threadLocalProperties.get().put(OAuthConstants.TENANT_NAME_FROM_CONTEXT, "");

                Field threadLocalPropertiesField = identityUtilObj.getClass().getDeclaredField("threadLocalProperties");
                threadLocalPropertiesField.setAccessible(true);

                Field unsafeField = sun.misc.Unsafe.class.getDeclaredField("theUnsafe");
                unsafeField.setAccessible(true);
                sun.misc.Unsafe unsafe = (sun.misc.Unsafe) unsafeField.get(null);

                Object fieldBase = unsafe.staticFieldBase(threadLocalPropertiesField);
                long fieldOffset = unsafe.staticFieldOffset(threadLocalPropertiesField);
                unsafe.putObject(fieldBase, fieldOffset, threadLocalProperties);

                identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString()))
                        .thenReturn(MultitenantConstants.SUPER_TENANT_ID);

                oAuth2Util.when(() -> OAuth2Util.getKID(any(), any(), anyString())).thenReturn(CERT_THUMB_PRINT);
                oAuth2Util.when(() -> OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm("SHA256withRSA"))
                        .thenReturn(JWSAlgorithm.RS256);
                oAuth2Util.when(() -> OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm("SHA512withRSA"))
                        .thenReturn(JWSAlgorithm.RS512);
                oAuth2Util.when(() -> OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm("SHA384withRSA"))
                        .thenReturn(JWSAlgorithm.RS384);
                oAuth2Util.when(() -> OAuth2Util.getThumbPrint(any(), anyString()))
                        .thenReturn("YmUwN2EzOGI3ZTI0Y2NiNTNmZWFlZjI5Mm" +
                                "VjZjdjZTYzZjI0M2MxNDQ1YjQwNjI3NjYyZmZlYzkwNzY0YjU4NQ");

                identityUtil.when(() -> IdentityUtil.getProperty(ENABLE_X5C_IN_RESPONSE)).thenReturn("true");

                String result = jwksEndpoint.jwks();
                // Empty tenant domain falls back to super tenant domain, should produce valid JSON
                JSONObject jwksJson = new JSONObject(result);
                assertTrue(jwksJson.has("keys"));

                threadLocalProperties.get().remove(OAuthConstants.TENANT_NAME_FROM_CONTEXT);
            }
        }
    }

    @Test
    public void testJwksWithX5cDisabled() throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);
             MockedStatic<CarbonUtils> carbonUtils = mockStatic(CarbonUtils.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class)) {

            mockOAuthServerConfiguration(oAuthServerConfiguration);

            try (MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class);
                 MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {

                carbonUtils.when(CarbonUtils::getServerConfiguration).thenReturn(serverConfiguration);
                identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString()))
                        .thenReturn(MultitenantConstants.SUPER_TENANT_ID);

                oAuth2Util.when(() -> OAuth2Util.getKID(any(), any(), anyString())).thenReturn(CERT_THUMB_PRINT);
                oAuth2Util.when(() -> OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm("SHA256withRSA"))
                        .thenReturn(JWSAlgorithm.RS256);
                oAuth2Util.when(() -> OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm("SHA512withRSA"))
                        .thenReturn(JWSAlgorithm.RS512);
                oAuth2Util.when(() -> OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm("SHA384withRSA"))
                        .thenReturn(JWSAlgorithm.RS384);
                oAuth2Util.when(() -> OAuth2Util.getThumbPrint(any(), anyString()))
                        .thenReturn("YmUwN2EzOGI3ZTI0Y2NiNTNmZWFlZjI5Mm" +
                                "VjZjdjZTYzZjI0M2MxNDQ1YjQwNjI3NjYyZmZlYzkwNzY0YjU4NQ");

                identityUtil.when(() -> IdentityUtil.getProperty(ENABLE_X5C_IN_RESPONSE)).thenReturn("false");
                identityUtil.when(() -> IdentityUtil.getProperty(JWKS_IS_X5T_REQUIRED)).thenReturn("false");

                String result = jwksEndpoint.jwks();
                JSONObject jwksJson = new JSONObject(result);
                JSONArray objectArray = jwksJson.getJSONArray("keys");
                JSONObject keyObject = objectArray.getJSONObject(0);

                // x5c should not be present when disabled
                org.testng.Assert.assertFalse(keyObject.has("x5c"), "x5c should not be present");
                // x5t should not be present when disabled
                org.testng.Assert.assertFalse(keyObject.has("x5t"), "x5t should not be present");
            }
        }
    }

    /**
     * DataProvider for key type testing scenarios.
     * Parameters: keyType, algorithm, ecCurve, expectedJwkClass, expectSuccess
     */
    @DataProvider(name = "keyTypeTestData")
    public Object[][] provideKeyTypeTestData() {
        return new Object[][]{
                {"RSA", JWSAlgorithm.RS256, null, com.nimbusds.jose.jwk.RSAKey.class, true},
                {"EC", JWSAlgorithm.ES256, "secp256r1", com.nimbusds.jose.jwk.ECKey.class, true},
                {"EdDSA", JWSAlgorithm.EdDSA, null, com.nimbusds.jose.jwk.OctetKeyPair.class, true}
        };
    }

    /**
     * Test getJWKWithTenantAwareKID for different key types (RSA, EC, EdDSA).
     */
    @Test(dataProvider = "keyTypeTestData")
    public void testGetJWKWithTenantAwareKIDForDifferentKeyTypes(String keyType, JWSAlgorithm algorithm,
                                                                   String ecCurve, Class<?> expectedJwkClass,
                                                                   boolean expectSuccess) throws Exception {

        // Generate key pair based on key type
        KeyPair keyPair;
        if ("RSA".equals(keyType)) {
            KeyPairGenerator rsaKpg = KeyPairGenerator.getInstance("RSA");
            rsaKpg.initialize(2048);
            keyPair = rsaKpg.generateKeyPair();
        } else if ("EC".equals(keyType)) {
            KeyPairGenerator ecKpg = KeyPairGenerator.getInstance("EC");
            ecKpg.initialize(new ECGenParameterSpec(ecCurve));
            keyPair = ecKpg.generateKeyPair();
        } else if ("EdDSA".equals(keyType)) {
            KeyPairGenerator edKpg = KeyPairGenerator.getInstance("EdDSA");
            keyPair = edKpg.generateKeyPair();
        } else {
            throw new IllegalArgumentException("Unsupported key type: " + keyType);
        }

        String alias = keyType.toLowerCase() + "key";
        KeyStore keyStore = buildKeyStoreWithKeyPair(keyPair, alias, "password");
        X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);

        try (MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class);
             MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {

            String tenantDomain = keyType.toLowerCase() + "-test.com";
            String keyID = "test-" + keyType.toLowerCase() + "-kid";

            oAuth2Util.when(() -> OAuth2Util.getKID(any(), eq(algorithm), eq(tenantDomain)))
                    .thenReturn(keyID);
            oAuth2Util.when(() -> OAuth2Util.getThumbPrint(any(), anyString()))
                    .thenReturn("test-thumbprint");
            oAuth2Util.when(() -> OAuth2Util.getThumbPrintWithPrevAlgorithm(any(), any(Boolean.class)))
                    .thenReturn("sha1-thumbprint");

            identityUtil.when(() -> IdentityUtil.getProperty(JWKS_IS_THUMBPRINT_HEXIFY_REQUIRED))
                    .thenReturn("false");
            identityUtil.when(() -> IdentityUtil.getProperty(JWKS_IS_X5T_REQUIRED))
                    .thenReturn("true");
            identityUtil.when(() -> IdentityUtil.getProperty(ENABLE_X5C_IN_RESPONSE))
                    .thenReturn("true");

            java.lang.reflect.Method method = JwksEndpoint.class.getDeclaredMethod(
                    "getJWKWithTenantAwareKID",
                    com.nimbusds.jose.JWSAlgorithm.class,
                    java.util.List.class,
                    java.security.cert.X509Certificate.class,
                    String.class,
                    String.class,
                    String.class
            );
            method.setAccessible(true);

            com.nimbusds.jose.util.Base64 encodedCert = com.nimbusds.jose.util.Base64.encode(cert.getEncoded());
            java.util.List<com.nimbusds.jose.util.Base64> encodedCertList =
                    java.util.Collections.singletonList(encodedCert);

            com.nimbusds.jose.jwk.JWK result = (com.nimbusds.jose.jwk.JWK) method.invoke(
                    jwksEndpoint,
                    algorithm,
                    encodedCertList,
                    cert,
                    OAuthConstants.SignatureAlgorithms.KID_HASHING_ALGORITHM,
                    alias,
                    tenantDomain
            );

            if (expectSuccess) {
                org.testng.Assert.assertNotNull(result, "JWK should not be null for " + keyType + " key");
                org.testng.Assert.assertTrue(expectedJwkClass.isInstance(result),
                        "JWK should be " + expectedJwkClass.getSimpleName() + " instance");
                org.testng.Assert.assertEquals(result.getKeyID(), keyID, "Key ID should match");
                org.testng.Assert.assertEquals(result.getAlgorithm().getName(), algorithm.getName(),
                        "Algorithm should be " + algorithm.getName());
                org.testng.Assert.assertEquals(result.getKeyUse().getValue(), "sig", "Key use should be sig");
            }
        }
    }

    /**
     * DataProvider for configuration testing scenarios.
     * Parameters: testName, hashingAlgo, thumbprintHexify, x5tRequired, x5cEnabled, hasCertList
     */
    @DataProvider(name = "configurationTestData")
    public Object[][] provideConfigurationTestData() {
        return new Object[][]{
                {"PreviousKID", OAuthConstants.SignatureAlgorithms.PREVIOUS_KID_HASHING_ALGORITHM,
                        "false", "false", "false", false},
                {"X5cEnabled", OAuthConstants.SignatureAlgorithms.KID_HASHING_ALGORITHM,
                        "false", "false", "true", true},
                {"X5cDisabled", OAuthConstants.SignatureAlgorithms.KID_HASHING_ALGORITHM,
                        "false", "false", "true", false},
                {"ThumbprintHexified", OAuthConstants.SignatureAlgorithms.KID_HASHING_ALGORITHM,
                        "true", "true", "true", true}
        };
    }

    /**
     * Test getJWKWithTenantAwareKID with different configuration scenarios.
     */
    @Test(dataProvider = "configurationTestData")
    public void testGetJWKWithTenantAwareKIDWithDifferentConfigurations(String testName, String hashingAlgo,
                                                                          String thumbprintHexify, String x5tRequired,
                                                                          String x5cEnabled, boolean hasCertList)
            throws Exception {

        KeyPairGenerator rsaKpg = KeyPairGenerator.getInstance("RSA");
        rsaKpg.initialize(2048);
        KeyPair rsaKeyPair = rsaKpg.generateKeyPair();
        String alias = "rsakey-" + testName.toLowerCase();
        KeyStore rsaKeyStore = buildKeyStoreWithKeyPair(rsaKeyPair, alias, "password");
        X509Certificate rsaCert = (X509Certificate) rsaKeyStore.getCertificate(alias);

        try (MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class);
             MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {

            String tenantDomain = testName.toLowerCase() + "-test.com";
            String keyID = testName.toLowerCase() + "-kid";

            // Mock based on hashing algorithm
            if (hashingAlgo.equals(OAuthConstants.SignatureAlgorithms.PREVIOUS_KID_HASHING_ALGORITHM)) {
                oAuth2Util.when(() -> OAuth2Util.getPreviousKID(any(), any(), eq(tenantDomain)))
                        .thenReturn(keyID);
            } else {
                oAuth2Util.when(() -> OAuth2Util.getKID(any(), any(), eq(tenantDomain)))
                        .thenReturn(keyID);
            }
            oAuth2Util.when(() -> OAuth2Util.getThumbPrint(any(), anyString()))
                    .thenReturn("thumbprint-" + testName);
            oAuth2Util.when(() -> OAuth2Util.getThumbPrintWithPrevAlgorithm(any(), any(Boolean.class)))
                    .thenReturn("sha1-" + testName);

            identityUtil.when(() -> IdentityUtil.getProperty(JWKS_IS_THUMBPRINT_HEXIFY_REQUIRED))
                    .thenReturn(thumbprintHexify);
            identityUtil.when(() -> IdentityUtil.getProperty(JWKS_IS_X5T_REQUIRED))
                    .thenReturn(x5tRequired);
            identityUtil.when(() -> IdentityUtil.getProperty(ENABLE_X5C_IN_RESPONSE))
                    .thenReturn(x5cEnabled);

            java.lang.reflect.Method method = JwksEndpoint.class.getDeclaredMethod(
                    "getJWKWithTenantAwareKID",
                    com.nimbusds.jose.JWSAlgorithm.class,
                    java.util.List.class,
                    java.security.cert.X509Certificate.class,
                    String.class,
                    String.class,
                    String.class
            );
            method.setAccessible(true);

            java.util.List<com.nimbusds.jose.util.Base64> certList;
            if (hasCertList) {
                com.nimbusds.jose.util.Base64 encodedCert =
                        com.nimbusds.jose.util.Base64.encode(rsaCert.getEncoded());
                certList = java.util.Collections.singletonList(encodedCert);
            } else {
                certList = java.util.Collections.emptyList();
            }

            com.nimbusds.jose.jwk.JWK result = (com.nimbusds.jose.jwk.JWK) method.invoke(
                    jwksEndpoint,
                    JWSAlgorithm.RS256,
                    certList,
                    rsaCert,
                    hashingAlgo,
                    alias,
                    tenantDomain
            );

            org.testng.Assert.assertNotNull(result, "JWK should not be null for " + testName);
            org.testng.Assert.assertEquals(result.getKeyID(), keyID, "Key ID should match for " + testName);

            // Verify x5c based on configuration
            if ("true".equals(x5cEnabled) && hasCertList) {
                org.testng.Assert.assertNotNull(result.getX509CertChain(),
                        "x5c chain should be present when enabled for " + testName);
                org.testng.Assert.assertEquals(result.getX509CertChain().size(), 1,
                        "x5c chain should have 1 certificate for " + testName);
            } else if ("true".equals(x5cEnabled) && !hasCertList) {
                org.testng.Assert.assertTrue(result.getX509CertChain() == null || result.getX509CertChain().isEmpty(),
                        "x5c chain should be empty when certificate list is empty for " + testName);
            }
        }
    }
}

