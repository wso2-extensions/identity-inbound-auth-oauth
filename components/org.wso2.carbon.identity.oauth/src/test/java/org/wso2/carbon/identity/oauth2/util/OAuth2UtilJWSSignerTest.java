/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.util;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.IdentityKeyStoreResolver;
import org.wso2.carbon.identity.core.util.IdentityKeyStoreResolverConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertSame;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.expectThrows;

/**
 * Tests for creating JWS signers for software keys and for keys whose key material is not accessible (keys held in
 * an HSM), and for resolving the key store provider of the OAuth signing key. JWE decryption with such keys is tested
 * through RequestParamRequestObjectBuilder and OIDCSessionManagementUtil.
 */
public class OAuth2UtilJWSSignerTest {

    private static final String ALLOW_WEAK_RSA_SIGNER_KEY = "allow_weak_rsa_signer_key";
    private static final String TENANT_DOMAIN = "hsm.com";

    private OpaqueRSAKeyTestProvider hsmProvider;
    private X509Certificate hsmCertificate;
    private KeyPair softwareKeyPair;

    @BeforeClass
    public void setUp() throws Exception {

        // OAuth2Util reads OAuthServerConfiguration in a static initializer.
        try (MockedStatic<OAuthServerConfiguration> serverConfiguration = mockStatic(OAuthServerConfiguration.class)) {
            serverConfiguration.when(OAuthServerConfiguration::getInstance)
                    .thenReturn(mock(OAuthServerConfiguration.class));
            Class.forName(OAuth2Util.class.getName());
        }
        hsmProvider = new OpaqueRSAKeyTestProvider(2048);
        hsmCertificate = certificateFor((RSAPublicKey) hsmProvider.getPublicKey());
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        softwareKeyPair = generator.generateKeyPair();
    }

    @AfterMethod
    public void tearDown() {

        System.clearProperty(ALLOW_WEAK_RSA_SIGNER_KEY);
    }

    @DataProvider(name = "rsaSigningAlgorithms")
    public Object[][] rsaSigningAlgorithms() {

        return new Object[][]{{JWSAlgorithm.RS256}, {JWSAlgorithm.RS384}, {JWSAlgorithm.RS512}, {JWSAlgorithm.PS256}};
    }

    @Test(dataProvider = "rsaSigningAlgorithms")
    public void testCreateJWSSignerWithSoftwareKey(JWSAlgorithm algorithm) throws Exception {

        JWSSigner signer = OAuth2Util.createJWSSigner(softwareKeyPair.getPrivate(), hsmProvider, null);

        // Software keys keep the default provider selection; the given provider is not used.
        assertNull(signer.getJCAContext().getProvider());
        assertTrue(signAndVerify(signer, algorithm, (RSAPublicKey) softwareKeyPair.getPublic()));
    }

    @Test(dataProvider = "rsaSigningAlgorithms")
    public void testCreateJWSSignerWithOpaqueKey(JWSAlgorithm algorithm) throws Exception {

        JWSSigner signer = OAuth2Util.createJWSSigner(hsmProvider.getPrivateKey(), hsmProvider, hsmCertificate);

        assertSame(signer.getJCAContext().getProvider(), hsmProvider);
        assertTrue(signAndVerify(signer, algorithm, (RSAPublicKey) hsmProvider.getPublicKey()));
    }

    @Test
    public void testOpaqueKeyWithoutProviderFailsForPS256() throws Exception {

        // Without the key store provider, JCA picks a software provider before it sees the key (the reason for
        // binding the signer to the key store provider).
        JWSSigner signer = OAuth2Util.createJWSSigner(hsmProvider.getPrivateKey(), null, hsmCertificate);

        expectThrows(JOSEException.class, () -> signAndVerify(signer, JWSAlgorithm.PS256,
                (RSAPublicKey) hsmProvider.getPublicKey()));
    }

    @Test
    public void testOpaqueWeakKeyIsRejected() throws Exception {

        OpaqueRSAKeyTestProvider weakProvider = new OpaqueRSAKeyTestProvider(1024);
        X509Certificate weakCertificate = certificateFor((RSAPublicKey) weakProvider.getPublicKey());

        IdentityOAuth2Exception e = expectThrows(IdentityOAuth2Exception.class,
                () -> OAuth2Util.createJWSSigner(weakProvider.getPrivateKey(), weakProvider, weakCertificate));
        assertTrue(e.getMessage().contains("1024"));
    }

    @Test
    public void testOpaqueWeakKeyIsAllowedWithSystemFlag() throws Exception {

        OpaqueRSAKeyTestProvider weakProvider = new OpaqueRSAKeyTestProvider(1024);
        X509Certificate weakCertificate = certificateFor((RSAPublicKey) weakProvider.getPublicKey());
        System.setProperty(ALLOW_WEAK_RSA_SIGNER_KEY, "true");

        JWSSigner signer = OAuth2Util.createJWSSigner(weakProvider.getPrivateKey(), weakProvider, weakCertificate);
        assertTrue(signAndVerify(signer, JWSAlgorithm.RS256, (RSAPublicKey) weakProvider.getPublicKey()));
    }

    @Test
    public void testOpaqueKeyWithoutCertificateIsRejected() {

        expectThrows(IdentityOAuth2Exception.class,
                () -> OAuth2Util.createJWSSigner(hsmProvider.getPrivateKey(), hsmProvider, null));
    }

    @Test
    public void testSoftwareWeakKeyIsStillRejectedByNimbus() throws Exception {

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024);
        PrivateKey weakKey = generator.generateKeyPair().getPrivate();

        expectThrows(IllegalArgumentException.class, () -> OAuth2Util.createJWSSigner(weakKey, null, null));
    }

    @Test
    public void testNonRSAKeyIsRejected() throws Exception {

        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(256);
        PrivateKey ecKey = generator.generateKeyPair().getPrivate();

        IdentityOAuth2Exception e = expectThrows(IdentityOAuth2Exception.class,
                () -> OAuth2Util.createJWSSigner(ecKey, null, null));
        assertTrue(e.getMessage().contains("RSA"), e.getMessage());
        // Also with weak keys allowed, where the key size is not checked.
        System.setProperty(ALLOW_WEAK_RSA_SIGNER_KEY, "true");
        expectThrows(IdentityOAuth2Exception.class, () -> OAuth2Util.createJWSSigner(ecKey, null, null));
    }

    @Test
    public void testSoftwareKeyMaterialIsNotCopied() throws Exception {

        // getEncoded() returns a new copy of a software key's private key material; only the format is read.
        RSAPrivateKey key = new NoEncodingRSAPrivateKey((RSAPrivateKey) softwareKeyPair.getPrivate());

        assertNull(OAuth2Util.createJWSSigner(key, hsmProvider, null).getJCAContext().getProvider());
        try (MockedStatic<IdentityKeyStoreResolver> resolverStatic = mockStatic(IdentityKeyStoreResolver.class)) {
            assertNull(OAuth2Util.getSigningKeyStoreProvider(TENANT_DOMAIN, key));
        }
    }

    @Test
    public void testGetSigningKeyStoreProviderForSoftwareKey() throws Exception {

        try (MockedStatic<IdentityKeyStoreResolver> resolverStatic = mockStatic(IdentityKeyStoreResolver.class)) {
            assertNull(OAuth2Util.getSigningKeyStoreProvider(TENANT_DOMAIN, softwareKeyPair.getPrivate()));
            resolverStatic.verify(IdentityKeyStoreResolver::getInstance, never());
        }
    }

    @Test
    public void testGetSigningKeyStoreProviderForOpaqueKey() throws Exception {

        IdentityKeyStoreResolver resolver = mock(IdentityKeyStoreResolver.class);
        KeyStore keyStore = mock(KeyStore.class);
        when(keyStore.getProvider()).thenReturn(hsmProvider);
        when(resolver.getKeyStore(TENANT_DOMAIN, IdentityKeyStoreResolverConstants.InboundProtocol.OAUTH))
                .thenReturn(keyStore);
        try (MockedStatic<IdentityKeyStoreResolver> resolverStatic = mockStatic(IdentityKeyStoreResolver.class)) {
            resolverStatic.when(IdentityKeyStoreResolver::getInstance).thenReturn(resolver);

            assertSame(OAuth2Util.getSigningKeyStoreProvider(TENANT_DOMAIN, hsmProvider.getPrivateKey()),
                    hsmProvider);
            verify(resolver).getKeyStore(TENANT_DOMAIN, IdentityKeyStoreResolverConstants.InboundProtocol.OAUTH);
        }
    }

    @DataProvider(name = "signJWTWithRSAKeys")
    public Object[][] signJWTWithRSAKeys() {

        return new Object[][]{
                // opaque (HSM-style) key, algorithm
                {true, JWSAlgorithm.RS256}, {true, JWSAlgorithm.PS256},
                {false, JWSAlgorithm.RS256}, {false, JWSAlgorithm.PS256}};
    }

    @Test(dataProvider = "signJWTWithRSAKeys")
    public void testSignJWTWithRSA(boolean opaqueKey, JWSAlgorithm algorithm) throws Exception {

        PrivateKey privateKey = opaqueKey ? hsmProvider.getPrivateKey() : softwareKeyPair.getPrivate();
        RSAPublicKey publicKey = (RSAPublicKey) (opaqueKey ? hsmProvider.getPublicKey() :
                softwareKeyPair.getPublic());
        X509Certificate certificate = certificateFor(publicKey);

        IdentityKeyStoreResolver resolver = mock(IdentityKeyStoreResolver.class);
        KeyStore keyStore = mock(KeyStore.class);
        when(keyStore.getProvider()).thenReturn(hsmProvider);
        when(resolver.getKeyStore(anyString(), any())).thenReturn(keyStore);

        try (MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class, Mockito.CALLS_REAL_METHODS);
             MockedStatic<IdentityKeyStoreResolver> resolverStatic = mockStatic(IdentityKeyStoreResolver.class)) {
            resolverStatic.when(IdentityKeyStoreResolver::getInstance).thenReturn(resolver);
            oAuth2Util.when(() -> OAuth2Util.getPrivateKey(TENANT_DOMAIN)).thenReturn(privateKey);
            oAuth2Util.when(() -> OAuth2Util.getCertificate(TENANT_DOMAIN)).thenReturn(certificate);
            oAuth2Util.when(() -> OAuth2Util.getKID(any(X509Certificate.class), any(JWSAlgorithm.class),
                    eq(TENANT_DOMAIN))).thenReturn("test-kid");
            oAuth2Util.when(OAuth2Util::isJWTX5tHexifyingRequired).thenReturn(false);
            oAuth2Util.when(OAuth2Util::isX5tEnabled).thenReturn(false);
            oAuth2Util.when(OAuth2Util::isX5tS256Enabled).thenReturn(false);

            JWT jwt = OAuth2Util.signJWTWithRSA(new JWTClaimsSet.Builder().subject("alice").build(), algorithm,
                    TENANT_DOMAIN);

            SignedJWT signedJWT = (SignedJWT) jwt;
            assertEquals(signedJWT.getHeader().getAlgorithm(), algorithm);
            assertEquals(signedJWT.getHeader().getKeyID(), "test-kid");
            assertTrue(signedJWT.verify(new RSASSAVerifier(publicKey)));
            if (!opaqueKey) {
                // Software keys never trigger a key store provider lookup.
                verify(resolver, never()).getKeyStore(anyString(), any());
            }
        }
    }

    private static boolean signAndVerify(JWSSigner signer, JWSAlgorithm algorithm, RSAPublicKey publicKey)
            throws JOSEException {

        SignedJWT jwt = new SignedJWT(new JWSHeader(algorithm), new JWTClaimsSet.Builder().subject("alice").build());
        jwt.sign(signer);
        return jwt.verify(new RSASSAVerifier(publicKey));
    }

    private static X509Certificate certificateFor(RSAPublicKey publicKey) {

        X509Certificate certificate = mock(X509Certificate.class);
        when(certificate.getPublicKey()).thenReturn(publicKey);
        return certificate;
    }

    /**
     * A software RSA key whose getEncoded() fails, to show that it is not called.
     */
    private static final class NoEncodingRSAPrivateKey implements RSAPrivateKey {

        private static final long serialVersionUID = 1L;
        private final RSAPrivateKey key;

        NoEncodingRSAPrivateKey(RSAPrivateKey key) {

            this.key = key;
        }

        @Override
        public BigInteger getPrivateExponent() {

            return key.getPrivateExponent();
        }

        @Override
        public BigInteger getModulus() {

            return key.getModulus();
        }

        @Override
        public String getAlgorithm() {

            return key.getAlgorithm();
        }

        @Override
        public String getFormat() {

            return key.getFormat();
        }

        @Override
        public byte[] getEncoded() {

            throw new AssertionError("getEncoded() must not be called.");
        }
    }
}
