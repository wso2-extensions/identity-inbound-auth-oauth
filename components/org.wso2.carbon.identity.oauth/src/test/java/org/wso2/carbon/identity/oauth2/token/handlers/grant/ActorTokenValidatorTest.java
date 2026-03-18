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

package org.wso2.carbon.identity.oauth2.token.handlers.grant;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.JWTSignatureValidationUtils;
import org.wso2.carbon.identity.oauth2.util.JWTUtils;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.text.ParseException;
import java.util.Date;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

@Listeners(MockitoTestNGListener.class)
public class ActorTokenValidatorTest {

    private static final String TENANT_DOMAIN = "carbon.super";
    private static final String ISSUER = "https://localhost:9443/oauth2/token";
    private static final String ACTOR_SUBJECT = "agent-user-001";

    @Mock
    private SignedJWT mockSignedJWT;

    @Mock
    private JWTClaimsSet mockClaimsSet;

    @Mock
    private IdentityProvider mockIdentityProvider;

    @Mock
    private OAuthServerConfiguration mockOAuthServerConfig;

    private MockedStatic<JWTUtils> mockedJWTUtils;
    private MockedStatic<OAuth2Util> mockedOAuth2Util;
    private MockedStatic<JWTSignatureValidationUtils> mockedJWTSignatureValidationUtils;
    private MockedStatic<OAuthServerConfiguration> mockedOAuthServerConfiguration;

    @BeforeMethod
    public void setUp() {

        mockedJWTUtils = mockStatic(JWTUtils.class);
        mockedOAuth2Util = mockStatic(OAuth2Util.class);
        mockedJWTSignatureValidationUtils = mockStatic(JWTSignatureValidationUtils.class);
        mockedOAuthServerConfiguration = mockStatic(OAuthServerConfiguration.class);

        mockedOAuthServerConfiguration.when(OAuthServerConfiguration::getInstance)
                .thenReturn(mockOAuthServerConfig);
        // Lenient: not all tests exercise the expiry/nbf path that calls getTimeStampSkewInSeconds()
        lenient().when(mockOAuthServerConfig.getTimeStampSkewInSeconds()).thenReturn(0L);
    }

    @AfterMethod
    public void tearDown() {

        try {
            if (mockedJWTUtils != null) {
                mockedJWTUtils.close();
            }
        } finally {
            try {
                if (mockedOAuth2Util != null) {
                    mockedOAuth2Util.close();
                }
            } finally {
                try {
                    if (mockedJWTSignatureValidationUtils != null) {
                        mockedJWTSignatureValidationUtils.close();
                    }
                } finally {
                    if (mockedOAuthServerConfiguration != null) {
                        mockedOAuthServerConfiguration.close();
                    }
                }
            }
        }
    }

    @Test
    public void testValidateAndGetSubject_validTokenWithMatchingIssuer_returnsActorSubject() throws Exception {

        mockedJWTUtils.when(() -> JWTUtils.parseJWT("valid.jwt.token")).thenReturn(mockSignedJWT);
        mockedJWTUtils.when(() -> JWTUtils.getJWTClaimSet(mockSignedJWT))
                .thenReturn(Optional.of(mockClaimsSet));
        when(mockClaimsSet.getIssuer()).thenReturn(ISSUER);
        when(mockClaimsSet.getExpirationTime()).thenReturn(new Date(System.currentTimeMillis() + 60000));
        when(mockClaimsSet.getNotBeforeTime()).thenReturn(null);
        when(mockClaimsSet.getSubject()).thenReturn(ACTOR_SUBJECT);
        mockedOAuth2Util.when(() -> OAuth2Util.getIdentityProviderWithJWTIssuer(ISSUER, TENANT_DOMAIN))
                .thenReturn(mockIdentityProvider);
        mockedJWTSignatureValidationUtils.when(() ->
                        JWTSignatureValidationUtils.validateSignature(mockSignedJWT, mockIdentityProvider,
                                TENANT_DOMAIN)).thenReturn(true);
        mockedJWTUtils.when(() -> JWTUtils.checkExpirationTime(any(Date.class))).thenReturn(true);
        mockedOAuth2Util.when(() -> OAuth2Util.getIdTokenIssuer(TENANT_DOMAIN)).thenReturn(ISSUER);

        String result = ActorTokenValidator.validateAndGetSubject("valid.jwt.token", TENANT_DOMAIN);

        Assert.assertEquals(result, ACTOR_SUBJECT);
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class,
            expectedExceptionsMessageRegExp = "Error while parsing the actor token JWT.")
    public void testValidateAndGetSubject_parseException_throwsIdentityOAuth2Exception() throws Exception {

        mockedJWTUtils.when(() -> JWTUtils.parseJWT("bad-token"))
                .thenThrow(new ParseException("Invalid JWT format", 0));

        ActorTokenValidator.validateAndGetSubject("bad-token", TENANT_DOMAIN);
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class,
            expectedExceptionsMessageRegExp = "Claim values are empty in the given actor token.")
    public void testValidateAndGetSubject_emptyClaimSet_throwsIdentityOAuth2Exception() throws Exception {

        mockedJWTUtils.when(() -> JWTUtils.parseJWT(anyString())).thenReturn(mockSignedJWT);
        mockedJWTUtils.when(() -> JWTUtils.getJWTClaimSet(mockSignedJWT))
                .thenReturn(Optional.empty());

        ActorTokenValidator.validateAndGetSubject("some.jwt.token", TENANT_DOMAIN);
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testValidateAndGetSubject_missingMandatoryClaims_throwsIdentityOAuth2Exception() throws Exception {

        mockedJWTUtils.when(() -> JWTUtils.parseJWT(anyString())).thenReturn(mockSignedJWT);
        mockedJWTUtils.when(() -> JWTUtils.getJWTClaimSet(mockSignedJWT))
                .thenReturn(Optional.of(mockClaimsSet));
        mockedJWTUtils.when(() -> JWTUtils.validateMandatoryClaims(mockClaimsSet))
                .thenThrow(new IdentityOAuth2Exception("Mandatory field - Issuer is empty in the given JWT"));

        ActorTokenValidator.validateAndGetSubject("some.jwt.token", TENANT_DOMAIN);
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class,
            expectedExceptionsMessageRegExp = "Signature or message authentication invalid for actor token.")
    public void testValidateAndGetSubject_invalidSignature_throwsIdentityOAuth2Exception() throws Exception {

        mockedJWTUtils.when(() -> JWTUtils.parseJWT(anyString())).thenReturn(mockSignedJWT);
        mockedJWTUtils.when(() -> JWTUtils.getJWTClaimSet(mockSignedJWT))
                .thenReturn(Optional.of(mockClaimsSet));
        when(mockClaimsSet.getIssuer()).thenReturn(ISSUER);
        mockedOAuth2Util.when(() -> OAuth2Util.getIdentityProviderWithJWTIssuer(anyString(), anyString()))
                .thenReturn(mockIdentityProvider);
        mockedJWTSignatureValidationUtils.when(() ->
                        JWTSignatureValidationUtils.validateSignature(any(), any(), anyString()))
                .thenReturn(false);

        ActorTokenValidator.validateAndGetSubject("some.jwt.token", TENANT_DOMAIN);
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class,
            expectedExceptionsMessageRegExp = "Token is used before Not_Before_Time.")
    public void testValidateAndGetSubject_notBeforeTimeViolation_throwsIdentityOAuth2Exception() throws Exception {

        mockedJWTUtils.when(() -> JWTUtils.parseJWT(anyString())).thenReturn(mockSignedJWT);
        mockedJWTUtils.when(() -> JWTUtils.getJWTClaimSet(mockSignedJWT))
                .thenReturn(Optional.of(mockClaimsSet));
        when(mockClaimsSet.getIssuer()).thenReturn(ISSUER);
        when(mockClaimsSet.getExpirationTime()).thenReturn(new Date(System.currentTimeMillis() + 60000));
        when(mockClaimsSet.getNotBeforeTime()).thenReturn(new Date(System.currentTimeMillis() + 60000));
        mockedOAuth2Util.when(() -> OAuth2Util.getIdentityProviderWithJWTIssuer(anyString(), anyString()))
                .thenReturn(mockIdentityProvider);
        mockedJWTSignatureValidationUtils.when(() ->
                        JWTSignatureValidationUtils.validateSignature(any(), any(), anyString()))
                .thenReturn(true);
        mockedJWTUtils.when(() -> JWTUtils.checkExpirationTime(any(Date.class))).thenReturn(true);
        mockedJWTUtils.when(() -> JWTUtils.checkNotBeforeTime(any(Date.class)))
                .thenThrow(new IdentityOAuth2Exception("Token is used before Not_Before_Time."));

        ActorTokenValidator.validateAndGetSubject("some.jwt.token", TENANT_DOMAIN);
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class,
            expectedExceptionsMessageRegExp = "Invalid issuer in the actor token.*")
    public void testValidateAndGetSubject_issuerMismatch_throwsIdentityOAuth2Exception() throws Exception {

        String differentIssuer = "https://some-other-issuer.com";
        mockedJWTUtils.when(() -> JWTUtils.parseJWT(anyString())).thenReturn(mockSignedJWT);
        mockedJWTUtils.when(() -> JWTUtils.getJWTClaimSet(mockSignedJWT))
                .thenReturn(Optional.of(mockClaimsSet));
        when(mockClaimsSet.getIssuer()).thenReturn(differentIssuer);
        when(mockClaimsSet.getExpirationTime()).thenReturn(new Date(System.currentTimeMillis() + 60000));
        when(mockClaimsSet.getNotBeforeTime()).thenReturn(null);
        mockedOAuth2Util.when(() -> OAuth2Util.getIdentityProviderWithJWTIssuer(differentIssuer, TENANT_DOMAIN))
                .thenReturn(mockIdentityProvider);
        mockedJWTSignatureValidationUtils.when(() ->
                        JWTSignatureValidationUtils.validateSignature(any(), any(), anyString()))
                .thenReturn(true);
        mockedJWTUtils.when(() -> JWTUtils.checkExpirationTime(any())).thenReturn(true);
        mockedOAuth2Util.when(() -> OAuth2Util.getIdTokenIssuer(TENANT_DOMAIN)).thenReturn(ISSUER);

        ActorTokenValidator.validateAndGetSubject("some.jwt.token", TENANT_DOMAIN);
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testValidateAndGetSubject_idpLookupFails_throwsIdentityOAuth2Exception() throws Exception {

        mockedJWTUtils.when(() -> JWTUtils.parseJWT(anyString())).thenReturn(mockSignedJWT);
        mockedJWTUtils.when(() -> JWTUtils.getJWTClaimSet(mockSignedJWT))
                .thenReturn(Optional.of(mockClaimsSet));
        when(mockClaimsSet.getIssuer()).thenReturn(ISSUER);
        mockedOAuth2Util.when(() -> OAuth2Util.getIdentityProviderWithJWTIssuer(anyString(), anyString()))
                .thenThrow(new IdentityOAuth2Exception("IDP lookup failed for issuer: " + ISSUER));

        ActorTokenValidator.validateAndGetSubject("some.jwt.token", TENANT_DOMAIN);
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testValidateAndGetSubject_getIdTokenIssuerFails_throwsIdentityOAuth2Exception() throws Exception {

        mockedJWTUtils.when(() -> JWTUtils.parseJWT(anyString())).thenReturn(mockSignedJWT);
        mockedJWTUtils.when(() -> JWTUtils.getJWTClaimSet(mockSignedJWT))
                .thenReturn(Optional.of(mockClaimsSet));
        when(mockClaimsSet.getIssuer()).thenReturn(ISSUER);
        when(mockClaimsSet.getExpirationTime()).thenReturn(new Date(System.currentTimeMillis() + 60000));
        when(mockClaimsSet.getNotBeforeTime()).thenReturn(null);
        mockedOAuth2Util.when(() -> OAuth2Util.getIdentityProviderWithJWTIssuer(anyString(), anyString()))
                .thenReturn(mockIdentityProvider);
        mockedJWTSignatureValidationUtils.when(() ->
                        JWTSignatureValidationUtils.validateSignature(any(), any(), anyString()))
                .thenReturn(true);
        mockedJWTUtils.when(() -> JWTUtils.checkExpirationTime(any())).thenReturn(true);
        mockedOAuth2Util.when(() -> OAuth2Util.getIdTokenIssuer(TENANT_DOMAIN))
                .thenThrow(new IdentityOAuth2Exception("Token issuer lookup error"));

        ActorTokenValidator.validateAndGetSubject("some.jwt.token", TENANT_DOMAIN);
    }

    @Test(expectedExceptions = IdentityOAuth2ClientException.class,
            expectedExceptionsMessageRegExp = "Actor token has expired.")
    public void testValidateAndGetSubject_expiredToken_throwsIdentityOAuth2ClientException() throws Exception {

        mockedJWTUtils.when(() -> JWTUtils.parseJWT(anyString())).thenReturn(mockSignedJWT);
        mockedJWTUtils.when(() -> JWTUtils.getJWTClaimSet(mockSignedJWT))
                .thenReturn(Optional.of(mockClaimsSet));
        when(mockClaimsSet.getIssuer()).thenReturn(ISSUER);
        when(mockClaimsSet.getExpirationTime()).thenReturn(new Date(System.currentTimeMillis() - 60000));
        mockedOAuth2Util.when(() -> OAuth2Util.getIdentityProviderWithJWTIssuer(ISSUER, TENANT_DOMAIN))
                .thenReturn(mockIdentityProvider);
        mockedJWTSignatureValidationUtils.when(() ->
                        JWTSignatureValidationUtils.validateSignature(any(), any(), anyString()))
                .thenReturn(true);
        mockedJWTUtils.when(() -> JWTUtils.checkExpirationTime(any(Date.class))).thenReturn(false);

        ActorTokenValidator.validateAndGetSubject("some.jwt.token", TENANT_DOMAIN);
    }

    @Test
    public void testValidateAndGetSubject_nullNotBeforeTime_noExceptionThrown() throws Exception {

        mockedJWTUtils.when(() -> JWTUtils.parseJWT(anyString())).thenReturn(mockSignedJWT);
        mockedJWTUtils.when(() -> JWTUtils.getJWTClaimSet(mockSignedJWT))
                .thenReturn(Optional.of(mockClaimsSet));
        when(mockClaimsSet.getIssuer()).thenReturn(ISSUER);
        when(mockClaimsSet.getExpirationTime()).thenReturn(new Date(System.currentTimeMillis() + 60000));
        when(mockClaimsSet.getNotBeforeTime()).thenReturn(null);
        when(mockClaimsSet.getSubject()).thenReturn(ACTOR_SUBJECT);
        mockedOAuth2Util.when(() -> OAuth2Util.getIdentityProviderWithJWTIssuer(ISSUER, TENANT_DOMAIN))
                .thenReturn(mockIdentityProvider);
        mockedJWTSignatureValidationUtils.when(() ->
                        JWTSignatureValidationUtils.validateSignature(any(), any(), anyString()))
                .thenReturn(true);
        mockedJWTUtils.when(() -> JWTUtils.checkExpirationTime(any(Date.class))).thenReturn(true);
        mockedOAuth2Util.when(() -> OAuth2Util.getIdTokenIssuer(TENANT_DOMAIN)).thenReturn(ISSUER);

        String result = ActorTokenValidator.validateAndGetSubject("some.jwt.token", TENANT_DOMAIN);

        Assert.assertEquals(result, ACTOR_SUBJECT);
    }
}
