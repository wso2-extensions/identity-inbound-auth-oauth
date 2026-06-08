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

package org.wso2.carbon.identity.oauth2.validators.jwt;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.proc.SimpleSecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;

import java.lang.reflect.Field;
import java.util.Collections;

import static org.mockito.Matchers.any;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

/**
 * Regression tests for issue #4989: signature verification failing when JWKS is provided
 * for tokens with {@code typ: at+jwt} (RFC 9068 access-token JWT type).
 *
 * Before the fix, {@link JWKSBasedJWTValidator}'s no-arg constructor instantiated a
 * Nimbus {@code DefaultJWTProcessor} without overriding its default {@code JWSTypeVerifier},
 * which from Nimbus 8.x onwards only accepts {@code typ=JWT} (or absent). Tokens with
 * {@code typ=at+jwt} were rejected with {@code BadJOSEException}.
 *
 * The fix registers a permissive {@code JWSTypeVerifier} that accepts any {@code typ} value,
 * preserving backward compatibility while fixing the regression for RFC 9068 tokens.
 */
@WithCarbonHome
@PrepareForTest({JWKSourceDataProvider.class, JWKSBasedJWTValidator.class})
public class JWKSBasedJWTValidatorTypeVerifierTest extends PowerMockIdentityBaseTest {

    private static final String TEST_KID = "test-kid-4989";
    private static final String TEST_JWKS_URI = "https://localhost:9444/oauth2/jwks";

    @Mock
    private JWKSourceDataProvider dataProvider;
    @Mock
    private RemoteJWKSet<SecurityContext> remoteJWKSet;

    @BeforeMethod
    public void setUp() {

        initMocks(this);
    }

    /**
     * Direct unit test on the {@code JWSTypeVerifier} configured by the constructor.
     * Verifies that a JWT with {@code typ=at+jwt} (RFC 9068) is accepted by the type verifier.
     * Without the fix, the verifier rejects {@code at+jwt} with
     * {@code BadJOSEException: JOSE header typ (type) at+jwt not allowed}.
     */
    @Test
    public void testJWSTypeVerifierAcceptsAtJwtType() throws Exception {

        JOSEObjectTypeVerifier<SecurityContext> typeVerifier = getJWSTypeVerifier(new JWKSBasedJWTValidator());
        assertNotNull(typeVerifier, "JWSTypeVerifier should be configured by the constructor.");
        try {
            typeVerifier.verify(new JOSEObjectType("at+jwt"), new SimpleSecurityContext());
        } catch (Exception e) {
            fail("typ=at+jwt should be accepted after the fix, but was rejected: " + e.getMessage());
        }
    }

    /**
     * Control: a JWT with the standard {@code typ=JWT} must continue to be accepted by the
     * type verifier. Asserts the fix did not break the pre-existing happy path.
     */
    @Test
    public void testJWSTypeVerifierAcceptsStandardJwtType() throws Exception {

        JOSEObjectTypeVerifier<SecurityContext> typeVerifier = getJWSTypeVerifier(new JWKSBasedJWTValidator());
        try {
            typeVerifier.verify(JOSEObjectType.JWT, new SimpleSecurityContext());
        } catch (Exception e) {
            fail("typ=JWT should remain accepted after the fix, but was rejected: " + e.getMessage());
        }
    }

    /**
     * Verifies the permissive nature of the fix: any other custom {@code typ} value is also
     * accepted (e.g., {@code foo+jwt}). This pins the actual fix behaviour — the verifier was
     * deliberately written to be permissive ("All types are valid" per the inline comment) for
     * backward compatibility — so future refactors that tighten it would fail this test and
     * require an intentional change.
     */
    @Test
    public void testJWSTypeVerifierAcceptsCustomType() throws Exception {

        JOSEObjectTypeVerifier<SecurityContext> typeVerifier = getJWSTypeVerifier(new JWKSBasedJWTValidator());
        try {
            typeVerifier.verify(new JOSEObjectType("foo+jwt"), new SimpleSecurityContext());
        } catch (Exception e) {
            fail("Custom typ=foo+jwt should be accepted by the permissive fix, but was rejected: "
                    + e.getMessage());
        }
    }

    /**
     * Verifies that the type verifier accepts a {@code null} type (i.e., absent {@code typ}
     * header). This is the same behavior Nimbus's {@code DefaultJOSEObjectTypeVerifier}
     * provided pre-8.x for unsigned/legacy tokens.
     */
    @Test
    public void testJWSTypeVerifierAcceptsNullType() throws Exception {

        JOSEObjectTypeVerifier<SecurityContext> typeVerifier = getJWSTypeVerifier(new JWKSBasedJWTValidator());
        try {
            typeVerifier.verify(null, new SimpleSecurityContext());
        } catch (Exception e) {
            fail("typ=<null> should be accepted, but was rejected: " + e.getMessage());
        }
    }

    /**
     * End-to-end regression test: signs a real RS256 JWT with {@code typ=at+jwt}, exposes the
     * matching public key via a mocked {@code RemoteJWKSet}, and asserts that
     * {@code validateSignature} returns {@code true}. Without the fix this throws
     * {@code IdentityOAuth2Exception("Signature validation failed for the provided JWT")}
     * because Nimbus's default type verifier rejects {@code at+jwt} before signature checking.
     */
    @Test
    public void testValidateSignatureWithAtJwtType() throws Exception {

        RSAKey rsaKey = new RSAKeyGenerator(2048).keyID(TEST_KID).generate();
        SignedJWT signedJWT = signJwt(rsaKey, new JOSEObjectType("at+jwt"));

        mockStatic(JWKSourceDataProvider.class);
        when(JWKSourceDataProvider.getInstance()).thenReturn(dataProvider);
        when(dataProvider.getJWKSource(TEST_JWKS_URI)).thenReturn(remoteJWKSet);
        when(remoteJWKSet.get(any(), any()))
                .thenReturn(Collections.<JWK>singletonList(rsaKey.toPublicJWK()));

        JWKSBasedJWTValidator validator = new JWKSBasedJWTValidator();
        boolean valid = validator.validateSignature(signedJWT, TEST_JWKS_URI, "RS256",
                Collections.<String, Object>emptyMap());
        assertTrue(valid, "JWT with typ=at+jwt must validate successfully after the fix.");
    }

    /**
     * Control: the same end-to-end flow with the standard {@code typ=JWT} also succeeds.
     */
    @Test
    public void testValidateSignatureWithStandardJwtType() throws Exception {

        RSAKey rsaKey = new RSAKeyGenerator(2048).keyID(TEST_KID).generate();
        SignedJWT signedJWT = signJwt(rsaKey, JOSEObjectType.JWT);

        mockStatic(JWKSourceDataProvider.class);
        when(JWKSourceDataProvider.getInstance()).thenReturn(dataProvider);
        when(dataProvider.getJWKSource(TEST_JWKS_URI)).thenReturn(remoteJWKSet);
        when(remoteJWKSet.get(any(), any()))
                .thenReturn(Collections.<JWK>singletonList(rsaKey.toPublicJWK()));

        JWKSBasedJWTValidator validator = new JWKSBasedJWTValidator();
        boolean valid = validator.validateSignature(signedJWT, TEST_JWKS_URI, "RS256",
                Collections.<String, Object>emptyMap());
        assertTrue(valid, "JWT with typ=JWT must continue to validate successfully.");
    }

    /**
     * Negative regression test: a JWT signed with one key but verified against a different
     * public key must still fail signature validation, even when {@code typ=at+jwt}. This
     * guards against the permissive type verifier accidentally weakening signature checks.
     */
    @Test
    public void testValidateSignatureFailsForTamperedSignatureWithAtJwtType() throws Exception {

        RSAKey signingKey = new RSAKeyGenerator(2048).keyID(TEST_KID).generate();
        RSAKey unrelatedKey = new RSAKeyGenerator(2048).keyID(TEST_KID).generate();
        SignedJWT signedJWT = signJwt(signingKey, new JOSEObjectType("at+jwt"));

        mockStatic(JWKSourceDataProvider.class);
        when(JWKSourceDataProvider.getInstance()).thenReturn(dataProvider);
        when(dataProvider.getJWKSource(TEST_JWKS_URI)).thenReturn(remoteJWKSet);
        when(remoteJWKSet.get(any(), any()))
                .thenReturn(Collections.<JWK>singletonList(unrelatedKey.toPublicJWK()));

        JWKSBasedJWTValidator validator = new JWKSBasedJWTValidator();
        try {
            validator.validateSignature(signedJWT, TEST_JWKS_URI, "RS256",
                    Collections.<String, Object>emptyMap());
            fail("Tampered signature should be rejected even with typ=at+jwt.");
        } catch (IdentityOAuth2Exception expected) {
            // Expected — signature must still be enforced.
        }
    }

    private SignedJWT signJwt(RSAKey rsaKey, JOSEObjectType type) throws Exception {

        JWSSigner signer = new RSASSASigner(rsaKey);
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .type(type)
                .keyID(rsaKey.getKeyID())
                .build();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject("alice")
                .issuer("https://test-idp.example.com")
                .build();
        SignedJWT signedJWT = new SignedJWT(header, claims);
        signedJWT.sign(signer);
        return signedJWT;
    }

    @SuppressWarnings("unchecked")
    private JOSEObjectTypeVerifier<SecurityContext> getJWSTypeVerifier(JWKSBasedJWTValidator validator)
            throws Exception {

        Field processorField = JWKSBasedJWTValidator.class.getDeclaredField("jwtProcessor");
        processorField.setAccessible(true);
        ConfigurableJWTProcessor<SecurityContext> processor =
                (ConfigurableJWTProcessor<SecurityContext>) processorField.get(validator);
        return (JOSEObjectTypeVerifier<SecurityContext>) processor.getJWSTypeVerifier();
    }
}
