/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.SignedJWT;
import org.mockito.MockedConstruction;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.RequestObjectException;
import org.wso2.carbon.identity.oauth2.validators.jwt.JWKSBasedJWTValidator;

import java.security.cert.Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.when;
import static org.testng.Assert.*;
import static org.wso2.carbon.identity.oauth.RequestObjectValidatorUtil.NIMBUS_ERROR_JWT_BEFORE_USE_TIME;
import static org.wso2.carbon.identity.oauth.RequestObjectValidatorUtil.NIMBUS_ERROR_JWT_EXPIRED;

public class RequestObjectValidatorUtilTest {

    @Test
    public void testIsSignatureVerifiedNBFError() {

        SignedJWT mockJwt = mock(SignedJWT.class);
        when(mockJwt.getParsedString()).thenReturn("dummy-jwt");

        JWSHeader mockHeader = mock(JWSHeader.class);
        when(mockJwt.getHeader()).thenReturn(mockHeader);
        when(mockHeader.getAlgorithm()).thenReturn(JWSAlgorithm.PS256);

        String jwksUri = "https://example.com/jwks";

        BadJOSEException badJOSEEx = new BadJOSEException(NIMBUS_ERROR_JWT_BEFORE_USE_TIME);
        IdentityOAuth2Exception ex =
                new IdentityOAuth2Exception("Signature validation failed for the provided JWT.", badJOSEEx);

        try (MockedConstruction<JWKSBasedJWTValidator> mocked = mockConstruction(JWKSBasedJWTValidator.class,
                (mock, context) -> {
                    when(mock.validateSignature(anyString(), anyString(), anyString(), anyMap())).thenThrow(ex);
                })) {

            RequestObjectValidatorUtil.isSignatureVerified(mockJwt, jwksUri);
            fail("Expected RequestObjectException was not thrown.");
        } catch (RequestObjectException e) {
            assertTrue(e.getMessage().contains("request object is not valid yet"),
                    "Expected error message to mention 'not valid yet'");
        }
    }

    @Test
    public void testIsSignatureVerifiedEXPError() {

        SignedJWT mockJwt = mock(SignedJWT.class);
        when(mockJwt.getParsedString()).thenReturn("dummy-jwt");

        JWSHeader mockHeader = mock(JWSHeader.class);
        when(mockJwt.getHeader()).thenReturn(mockHeader);
        when(mockHeader.getAlgorithm()).thenReturn(JWSAlgorithm.PS256);

        String jwksUri = "https://example.com/jwks";

        BadJOSEException badJOSEEx = new BadJOSEException(NIMBUS_ERROR_JWT_EXPIRED);
        IdentityOAuth2Exception ex =
                new IdentityOAuth2Exception("Signature validation failed for the provided JWT.", badJOSEEx);

        try (MockedConstruction<JWKSBasedJWTValidator> mocked = mockConstruction(JWKSBasedJWTValidator.class,
                (mock, context) -> {
                    when(mock.validateSignature(anyString(), anyString(), anyString(), anyMap())).thenThrow(ex);
                })) {

            RequestObjectValidatorUtil.isSignatureVerified(mockJwt, jwksUri);
            fail("Expected RequestObjectException was not thrown.");
        } catch (RequestObjectException e) {
            assertTrue(e.getMessage().contains("request object is expired"),
                    "Expected error message to mention 'expired'");
        }
    }

    @Test
    public void testIsSignatureVerifiedOtherError() {

        SignedJWT mockJwt = mock(SignedJWT.class);
        when(mockJwt.getParsedString()).thenReturn("dummy-jwt");

        JWSHeader mockHeader = mock(JWSHeader.class);
        when(mockJwt.getHeader()).thenReturn(mockHeader);
        when(mockHeader.getAlgorithm()).thenReturn(JWSAlgorithm.PS256);

        String jwksUri = "https://example.com/jwks";

        BadJOSEException badJOSEEx = new BadJOSEException("Some other error occurred during JWT validation.");
        IdentityOAuth2Exception ex =
                new IdentityOAuth2Exception("Signature validation failed for the provided JWT.", badJOSEEx);

        try (MockedConstruction<JWKSBasedJWTValidator> mocked = mockConstruction(JWKSBasedJWTValidator.class,
                (mock, context) -> {
                    when(mock.validateSignature(anyString(), anyString(), anyString(), anyMap())).thenThrow(ex);
                })) {

            RequestObjectValidatorUtil.isSignatureVerified(mockJwt, jwksUri);
            fail("Expected RequestObjectException was not thrown.");
        } catch (RequestObjectException e) {
            assertTrue(e.getMessage()
                            .contains("Error occurred while validating request object signature using jwks endpoint"),
                    "Expected error message to mention 'expired'");
        }
    }

    @Test
    public void testIsSignatureVerifiedCauseMessageNull() {

        SignedJWT mockJwt = mock(SignedJWT.class);
        when(mockJwt.getParsedString()).thenReturn("dummy-jwt");

        JWSHeader mockHeader = mock(JWSHeader.class);
        when(mockJwt.getHeader()).thenReturn(mockHeader);
        when(mockHeader.getAlgorithm()).thenReturn(JWSAlgorithm.PS256);

        String jwksUri = "https://example.com/jwks";

        // IdentityOAuth2Exception with no cause and null message
        IdentityOAuth2Exception ex = new IdentityOAuth2Exception(null, (Throwable) null);

        try (MockedConstruction<JWKSBasedJWTValidator> mocked = mockConstruction(JWKSBasedJWTValidator.class,
                (mock, context) -> {
                    when(mock.validateSignature(anyString(), anyString(), anyString(), anyMap())).thenThrow(ex);
                })) {

            RequestObjectValidatorUtil.isSignatureVerified(mockJwt, jwksUri);
            fail("Expected RequestObjectException was not thrown.");
        } catch (RequestObjectException e) {
            assertTrue(e.getMessage()
                            .contains("Error occurred while validating request object signature using jwks endpoint"),
                    "Expected fallback error message to be present");
        }
    }

    @Test
    public void testPS256SignatureVerifiedWithRSACert() {

        SignedJWT mockJwt = mock(SignedJWT.class);
        when(mockJwt.getParsedString()).thenReturn("dummy-jwt");

        JWSHeader mockHeader = mock(JWSHeader.class);
        when(mockJwt.getHeader()).thenReturn(mockHeader);
        when(mockHeader.getAlgorithm()).thenReturn(JWSAlgorithm.PS256);

        Certificate mockCert = mock(Certificate.class);
        RSAPublicKey mockPk = mock(RSAPublicKey.class);

        when(mockCert.getPublicKey()).thenReturn(mockPk);

        RequestObjectValidatorUtil.isSignatureVerified(mockJwt, mockCert);
    }

    @Test
    public void testRS256SignatureVerifiedWithRSACert() {

        SignedJWT mockJwt = mock(SignedJWT.class);
        when(mockJwt.getParsedString()).thenReturn("dummy-jwt");

        JWSHeader mockHeader = mock(JWSHeader.class);
        when(mockJwt.getHeader()).thenReturn(mockHeader);
        when(mockHeader.getAlgorithm()).thenReturn(JWSAlgorithm.RS256);

        Certificate mockCert = mock(Certificate.class);
        RSAPublicKey mockPk = mock(RSAPublicKey.class);

        when(mockCert.getPublicKey()).thenReturn(mockPk);

        RequestObjectValidatorUtil.isSignatureVerified(mockJwt, mockCert);
    }

    @Test
    public void testSignatureVerifiedWithECCert() {

        SignedJWT mockJwt = mock(SignedJWT.class);
        when(mockJwt.getParsedString()).thenReturn("dummy-jwt");

        JWSHeader mockHeader = mock(JWSHeader.class);
        when(mockJwt.getHeader()).thenReturn(mockHeader);
        when(mockHeader.getAlgorithm()).thenReturn(JWSAlgorithm.ES256);

        Certificate mockCert = mock(Certificate.class);
        ECPublicKey mockPk = mock(ECPublicKey.class);

        when(mockCert.getPublicKey()).thenReturn(mockPk);

        RequestObjectValidatorUtil.isSignatureVerified(mockJwt, mockCert);
    }

    @Test
    public void testSignatureVerifiedWithECMismatchCert() {

        SignedJWT mockJwt = mock(SignedJWT.class);
        when(mockJwt.getParsedString()).thenReturn("dummy-jwt");

        JWSHeader mockHeader = mock(JWSHeader.class);
        when(mockJwt.getHeader()).thenReturn(mockHeader);
        when(mockHeader.getAlgorithm()).thenReturn(JWSAlgorithm.PS256);

        Certificate mockCert = mock(Certificate.class);
        ECPublicKey mockPk = mock(ECPublicKey.class);

        when(mockCert.getPublicKey()).thenReturn(mockPk);

        RequestObjectValidatorUtil.isSignatureVerified(mockJwt, mockCert);
    }

    @Test
    public void testSignatureVerifiedWithRSAMismatchCert() {

        SignedJWT mockJwt = mock(SignedJWT.class);
        when(mockJwt.getParsedString()).thenReturn("dummy-jwt");

        JWSHeader mockHeader = mock(JWSHeader.class);
        when(mockJwt.getHeader()).thenReturn(mockHeader);
        when(mockHeader.getAlgorithm()).thenReturn(JWSAlgorithm.ES256);

        Certificate mockCert = mock(Certificate.class);
        RSAPublicKey mockPk = mock(RSAPublicKey.class);

        when(mockCert.getPublicKey()).thenReturn(mockPk);

        RequestObjectValidatorUtil.isSignatureVerified(mockJwt, mockCert);
    }

    @Test
    public void testSignatureVerifiedUnsupportedAlgo() {

        SignedJWT mockJwt = mock(SignedJWT.class);
        when(mockJwt.getParsedString()).thenReturn("dummy-jwt");

        JWSHeader mockHeader = mock(JWSHeader.class);
        when(mockJwt.getHeader()).thenReturn(mockHeader);
        when(mockHeader.getAlgorithm()).thenReturn(JWSAlgorithm.EdDSA);

        Certificate mockCert = mock(Certificate.class);

        assertFalse(RequestObjectValidatorUtil.isSignatureVerified(mockJwt, mockCert));
    }
}
