/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.util;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.mockito.MockedStatic;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.IdentityKeyStoreResolver;
import org.wso2.carbon.identity.core.util.IdentityKeyStoreResolverConstants;
import org.wso2.carbon.identity.core.util.IdentityKeyStoreResolverException;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.keyidprovider.DefaultKeyIDProviderImpl;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.Date;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertSame;
import static org.testng.Assert.assertTrue;
import static org.wso2.carbon.identity.openidconnect.util.TestUtils.getKeyStoreFromFile;

/**
 * Tests for resolving the signing certificate of a JWT using the 'kid' in the JWT header.
 */
@WithCarbonHome
public class OAuth2UtilKIDResolutionTest {

    private static final String PASSWORD = "wso2carbon";
    private static final String CURRENT_KEY_ALIAS = "wso2carbon";
    private static final String PREVIOUS_KEY_ALIAS = "previous";
    private static final String TRUSTED_CERT_ALIAS = "localhost";
    private static final String EC_KEY_ALIAS = "wso2carbon_ec";
    private static final String TENANT_DOMAIN = "wso2.com";
    private static final String SUPER_TENANT = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;

    private KeyStore primaryKeyStore;
    private IdentityKeyStoreResolver identityKeyStoreResolver;
    private Certificate currentCertificate;
    private Certificate previousCertificate;

    private MockedStatic<IdentityUtil> identityUtil;
    private MockedStatic<IdentityKeyStoreResolver> identityKeyStoreResolverStatic;

    @BeforeMethod
    public void setUp() throws Exception {

        String carbonHome = System.getProperty(CarbonBaseConstants.CARBON_HOME);
        // Primary keystore after a key rotation: the current key, the previous key and trusted certificates.
        primaryKeyStore = getKeyStoreFromFile("wso2carbon.jks", PASSWORD, carbonHome);
        KeyStore previousKeyStore = getKeyStoreFromFile("testkeystore.jks", PASSWORD, carbonHome);
        primaryKeyStore.setKeyEntry(PREVIOUS_KEY_ALIAS,
                previousKeyStore.getKey(CURRENT_KEY_ALIAS, PASSWORD.toCharArray()), PASSWORD.toCharArray(),
                previousKeyStore.getCertificateChain(CURRENT_KEY_ALIAS));
        currentCertificate = primaryKeyStore.getCertificate(CURRENT_KEY_ALIAS);
        previousCertificate = primaryKeyStore.getCertificate(PREVIOUS_KEY_ALIAS);

        OAuth2ServiceComponentHolder.setKeyIDProvider(new DefaultKeyIDProviderImpl());
        // Initialize OAuth2Util before IdentityUtil is mocked, as its static fields read the identity configuration.
        Class.forName(OAuth2Util.class.getName());

        identityUtil = mockStatic(IdentityUtil.class);
        identityKeyStoreResolver = mock(IdentityKeyStoreResolver.class);
        identityKeyStoreResolverStatic = mockStatic(IdentityKeyStoreResolver.class);
        identityKeyStoreResolverStatic.when(IdentityKeyStoreResolver::getInstance)
                .thenReturn(identityKeyStoreResolver);
        when(identityKeyStoreResolver.getKeyStore(SUPER_TENANT,
                IdentityKeyStoreResolverConstants.InboundProtocol.OAUTH)).thenReturn(primaryKeyStore);
        when(identityKeyStoreResolver.getCertificate(SUPER_TENANT,
                IdentityKeyStoreResolverConstants.InboundProtocol.OAUTH)).thenReturn(currentCertificate);
    }

    @AfterMethod
    public void tearDown() {

        identityUtil.close();
        identityKeyStoreResolverStatic.close();
    }

    @DataProvider(name = "resolveSigningKeyByKIDConfigData")
    public Object[][] resolveSigningKeyByKIDConfigData() {

        return new Object[][]{
                // Configured value, expected result.
                {null, false},
                {"false", false},
                {"true", true}
        };
    }

    @Test(dataProvider = "resolveSigningKeyByKIDConfigData")
    public void testIsResolveSigningKeyByKIDEnabled(String configuredValue, boolean expected) {

        identityUtil.when(() -> IdentityUtil.getProperty(OAuth2Util.RESOLVE_SIGNING_KEY_BY_KID))
                .thenReturn(configuredValue);

        assertEquals(OAuth2Util.isResolveSigningKeyByKIDEnabled(), expected);
    }

    @Test
    public void testResolvePreviousKey() throws Exception {

        assertSame(resolve(header(JWSAlgorithm.RS256, kidOf(previousCertificate))), previousCertificate);
    }

    @Test
    public void testResolveCurrentKey() throws Exception {

        assertSame(resolve(header(JWSAlgorithm.RS256, kidOf(currentCertificate))), currentCertificate);
    }

    @Test
    public void testResolvePreviousKeyWithPSAlgorithm() throws Exception {

        JWSHeader header = header(JWSAlgorithm.PS256,
                OAuth2Util.getKID(previousCertificate, JWSAlgorithm.PS256, SUPER_TENANT));

        assertSame(resolve(header), previousCertificate);
    }

    @Test
    public void testUnknownKIDFallsBackToDefault() throws Exception {

        assertSame(resolve(header(JWSAlgorithm.RS256, "unknown_RS256")), currentCertificate);
    }

    @Test
    public void testUnknownKIDWithoutDefaultReturnsNull() throws Exception {

        assertNull(OAuth2Util.resolveSigningCertificateByKID(header(JWSAlgorithm.RS256, "unknown_RS256"),
                SUPER_TENANT, null));
    }

    @Test
    public void testNoKIDDoesNotLoadKeyStore() throws Exception {

        assertSame(resolve(new JWSHeader.Builder(JWSAlgorithm.RS256).build()), currentCertificate);
        verify(identityKeyStoreResolver, never()).getKeyStore(anyString(), any());
    }

    @Test
    public void testKIDOfAnotherAlgorithmFallsBackToDefault() throws Exception {

        assertSame(resolve(header(JWSAlgorithm.ES256, kidOf(previousCertificate))), currentCertificate);
    }

    @Test
    public void testTrustedCertificateEntryIsNotAccepted() throws Exception {

        assertTrue(primaryKeyStore.isCertificateEntry(TRUSTED_CERT_ALIAS));
        Certificate trustedCertificate = primaryKeyStore.getCertificate(TRUSTED_CERT_ALIAS);

        assertSame(resolve(header(JWSAlgorithm.RS256, kidOf(trustedCertificate))), currentCertificate);
    }

    @Test
    public void testNonRSAKeyEntryIsNotAccepted() throws Exception {

        assertTrue(primaryKeyStore.isKeyEntry(EC_KEY_ALIAS));
        Certificate ecCertificate = primaryKeyStore.getCertificate(EC_KEY_ALIAS);

        assertSame(resolve(header(JWSAlgorithm.RS256, kidOf(ecCertificate))), currentCertificate);
    }

    @Test
    public void testKIDErrorOfOneKeyEntryDoesNotSkipOthers() throws Exception {

        DefaultKeyIDProviderImpl defaultKeyIDProvider = new DefaultKeyIDProviderImpl();
        String previousKID = kidOf(previousCertificate);
        OAuth2ServiceComponentHolder.setKeyIDProvider((certificate, algorithm, tenantDomain) -> {
            if (certificate.equals(currentCertificate)) {
                throw new IdentityOAuth2Exception("Unable to compute the kid.");
            }
            return defaultKeyIDProvider.getKeyId(certificate, algorithm, tenantDomain);
        });

        try {
            assertSame(resolve(header(JWSAlgorithm.RS256, previousKID)), previousCertificate);
        } finally {
            OAuth2ServiceComponentHolder.setKeyIDProvider(defaultKeyIDProvider);
        }
    }

    @Test
    public void testResolveFromSigningTenantKeyStore() throws Exception {

        KeyStore tenantKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        tenantKeyStore.load(null, PASSWORD.toCharArray());
        tenantKeyStore.setKeyEntry(TENANT_DOMAIN, primaryKeyStore.getKey(PREVIOUS_KEY_ALIAS, PASSWORD.toCharArray()),
                PASSWORD.toCharArray(), primaryKeyStore.getCertificateChain(PREVIOUS_KEY_ALIAS));
        when(identityKeyStoreResolver.getKeyStore(TENANT_DOMAIN,
                IdentityKeyStoreResolverConstants.InboundProtocol.OAUTH)).thenReturn(tenantKeyStore);
        JWSHeader header = header(JWSAlgorithm.RS256,
                OAuth2Util.getKID(previousCertificate, JWSAlgorithm.RS256, TENANT_DOMAIN));

        Certificate resolved = OAuth2Util.resolveSigningCertificateByKID(header, TENANT_DOMAIN, currentCertificate);

        assertSame(resolved, previousCertificate);
        verify(identityKeyStoreResolver, never()).getKeyStore(SUPER_TENANT,
                IdentityKeyStoreResolverConstants.InboundProtocol.OAUTH);
    }

    @Test
    public void testKeyStoreErrorFallsBackToDefault() throws Exception {

        when(identityKeyStoreResolver.getKeyStore(SUPER_TENANT,
                IdentityKeyStoreResolverConstants.InboundProtocol.OAUTH))
                .thenThrow(new IdentityKeyStoreResolverException("IKSR-00000", "Keystore not available."));

        assertSame(resolve(header(JWSAlgorithm.RS256, kidOf(previousCertificate))), currentCertificate);
    }

    @Test
    public void testKeyEntriesAreNotCached() throws Exception {

        String previousKID = kidOf(previousCertificate);
        assertSame(resolve(header(JWSAlgorithm.RS256, previousKID)), previousCertificate);

        primaryKeyStore.deleteEntry(PREVIOUS_KEY_ALIAS);

        assertSame(resolve(header(JWSAlgorithm.RS256, previousKID)), currentCertificate);
    }

    @DataProvider(name = "idTokenValidationData")
    public Object[][] idTokenValidationData() {

        return new Object[][]{
                // Signing key alias, resolve signing certificate by kid, expected signature validity.
                {CURRENT_KEY_ALIAS, false, true},
                {CURRENT_KEY_ALIAS, true, true},
                {PREVIOUS_KEY_ALIAS, false, false},
                {PREVIOUS_KEY_ALIAS, true, true}
        };
    }

    @Test(dataProvider = "idTokenValidationData")
    public void testValidateIdTokenAfterKeyRotation(String signingKeyAlias, boolean resolveByKID,
                                                    boolean expectedValidity) throws Exception {

        identityUtil.when(() -> IdentityUtil.getProperty(OAuth2Util.RESOLVE_SIGNING_KEY_BY_KID))
                .thenReturn(String.valueOf(resolveByKID));
        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration =
                     mockStatic(OAuthServerConfiguration.class)) {
            oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance)
                    .thenReturn(mock(OAuthServerConfiguration.class));

            assertEquals(OAuth2Util.validateIdToken(buildIdToken(signingKeyAlias)), expectedValidity);
        }
    }

    private Certificate resolve(JWSHeader header) {

        return OAuth2Util.resolveSigningCertificateByKID(header, SUPER_TENANT, currentCertificate);
    }

    private String kidOf(Certificate certificate) throws Exception {

        return OAuth2Util.getKID(certificate, JWSAlgorithm.RS256, SUPER_TENANT);
    }

    private static JWSHeader header(JWSAlgorithm algorithm, String kid) {

        return new JWSHeader.Builder(algorithm).keyID(kid).build();
    }

    private String buildIdToken(String signingKeyAlias) throws Exception {

        PrivateKey privateKey = (PrivateKey) primaryKeyStore.getKey(signingKeyAlias, PASSWORD.toCharArray());
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("admin")
                .audience("clientId")
                .issuer("https://localhost:9443/oauth2/token")
                .expirationTime(new Date(System.currentTimeMillis() + 3600 * 1000))
                .build();
        SignedJWT signedJWT = new SignedJWT(header(JWSAlgorithm.RS256,
                kidOf(primaryKeyStore.getCertificate(signingKeyAlias))), claimsSet);
        signedJWT.sign(new RSASSASigner(privateKey));
        return signedJWT.serialize();
    }
}
