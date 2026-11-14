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

package org.wso2.carbon.identity.oauth2.validators;

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
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.IdentityKeyStoreResolver;
import org.wso2.carbon.identity.core.util.IdentityKeyStoreResolverConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.keyidprovider.DefaultKeyIDProviderImpl;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.organization.management.service.util.OrganizationManagementUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.lang.reflect.Method;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.Collections;
import java.util.Date;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.wso2.carbon.identity.openidconnect.util.TestUtils.getKeyStoreFromFile;

/**
 * Tests the signature validation of JWT access tokens in {@link OAuth2JWTTokenValidator} after a key rotation.
 */
@WithCarbonHome
public class OAuth2JWTTokenValidatorKIDTest {

    private static final String PASSWORD = "wso2carbon";
    private static final String CURRENT_KEY_ALIAS = "wso2carbon";
    private static final String PREVIOUS_KEY_ALIAS = "previous";
    private static final String SUPER_TENANT = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;

    private KeyStore primaryKeyStore;
    private MockedStatic<IdentityUtil> identityUtil;
    private MockedStatic<IdentityTenantUtil> identityTenantUtil;
    private MockedStatic<PrivilegedCarbonContext> privilegedCarbonContext;
    private MockedStatic<IdentityKeyStoreResolver> identityKeyStoreResolverStatic;
    private MockedStatic<OrganizationManagementUtil> organizationManagementUtil;

    @BeforeMethod
    public void setUp() throws Exception {

        String carbonHome = System.getProperty(CarbonBaseConstants.CARBON_HOME);
        // Primary keystore after a key rotation: the previous key is kept as a key entry.
        primaryKeyStore = getKeyStoreFromFile("wso2carbon.jks", PASSWORD, carbonHome);
        KeyStore previousKeyStore = getKeyStoreFromFile("testkeystore.jks", PASSWORD, carbonHome);
        primaryKeyStore.setKeyEntry(PREVIOUS_KEY_ALIAS,
                previousKeyStore.getKey(CURRENT_KEY_ALIAS, PASSWORD.toCharArray()), PASSWORD.toCharArray(),
                previousKeyStore.getCertificateChain(CURRENT_KEY_ALIAS));

        OAuth2ServiceComponentHolder.setKeyIDProvider(new DefaultKeyIDProviderImpl());
        // Initialize OAuth2Util before IdentityUtil is mocked, as its static fields read the identity configuration.
        Class.forName(OAuth2Util.class.getName());

        identityUtil = mockStatic(IdentityUtil.class);
        identityTenantUtil = mockStatic(IdentityTenantUtil.class);
        identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(SUPER_TENANT))
                .thenReturn(MultitenantConstants.SUPER_TENANT_ID);
        IdentityKeyStoreResolver identityKeyStoreResolver = mock(IdentityKeyStoreResolver.class);
        identityKeyStoreResolverStatic = mockStatic(IdentityKeyStoreResolver.class);
        identityKeyStoreResolverStatic.when(IdentityKeyStoreResolver::getInstance)
                .thenReturn(identityKeyStoreResolver);
        when(identityKeyStoreResolver.getKeyStore(SUPER_TENANT,
                IdentityKeyStoreResolverConstants.InboundProtocol.OAUTH)).thenReturn(primaryKeyStore);
        // The current certificate of the tenant.
        when(identityKeyStoreResolver.getCertificate(SUPER_TENANT,
                IdentityKeyStoreResolverConstants.InboundProtocol.OAUTH))
                .thenReturn(primaryKeyStore.getCertificate(CURRENT_KEY_ALIAS));
        PrivilegedCarbonContext carbonContext = mock(PrivilegedCarbonContext.class);
        when(carbonContext.getTenantDomain()).thenReturn(SUPER_TENANT);
        privilegedCarbonContext = mockStatic(PrivilegedCarbonContext.class);
        privilegedCarbonContext.when(PrivilegedCarbonContext::getThreadLocalCarbonContext).thenReturn(carbonContext);
        organizationManagementUtil = mockStatic(OrganizationManagementUtil.class);
        organizationManagementUtil.when(() -> OrganizationManagementUtil.isOrganization(anyString()))
                .thenReturn(false);
    }

    @AfterMethod
    public void tearDown() {

        identityUtil.close();
        identityTenantUtil.close();
        privilegedCarbonContext.close();
        identityKeyStoreResolverStatic.close();
        organizationManagementUtil.close();
    }

    @DataProvider(name = "signatureValidationData")
    public Object[][] signatureValidationData() {

        return new Object[][]{
                // Signing key alias, resolve signing certificate by kid, realm claim, expected signature validity.
                {CURRENT_KEY_ALIAS, null, true, true},
                {CURRENT_KEY_ALIAS, "true", true, true},
                {PREVIOUS_KEY_ALIAS, null, true, false},
                {PREVIOUS_KEY_ALIAS, "false", true, false},
                {PREVIOUS_KEY_ALIAS, "true", true, true},
                // Without a realm claim, e.g. when the token is signed with the SP tenant key (default).
                {CURRENT_KEY_ALIAS, null, false, true},
                {CURRENT_KEY_ALIAS, "true", false, true},
                {PREVIOUS_KEY_ALIAS, null, false, false},
                {PREVIOUS_KEY_ALIAS, "false", false, false},
                {PREVIOUS_KEY_ALIAS, "true", false, true}
        };
    }

    @Test(dataProvider = "signatureValidationData")
    public void testValidateSignatureAfterKeyRotation(String signingKeyAlias, String resolveByKID, boolean withRealm,
                                                      boolean expectedValidity) throws Exception {

        identityUtil.when(() -> IdentityUtil.getProperty(OAuth2Util.RESOLVE_SIGNING_KEY_BY_KID))
                .thenReturn(resolveByKID);
        SignedJWT signedJWT = SignedJWT.parse(buildAccessToken(signingKeyAlias, withRealm));
        IdentityProvider residentIdentityProvider = new IdentityProvider();
        residentIdentityProvider.setIdentityProviderName(IdentityApplicationConstants.RESIDENT_IDP_RESERVED_NAME);

        Method validateSignature = OAuth2JWTTokenValidator.class.getDeclaredMethod("validateSignature",
                SignedJWT.class, IdentityProvider.class, String.class);
        validateSignature.setAccessible(true);
        boolean isValid = (boolean) validateSignature.invoke(new OAuth2JWTTokenValidator(), signedJWT,
                residentIdentityProvider, SUPER_TENANT);

        assertEquals(isValid, expectedValidity);
    }

    private String buildAccessToken(String signingKeyAlias, boolean withRealm) throws Exception {

        PrivateKey privateKey = (PrivateKey) primaryKeyStore.getKey(signingKeyAlias, PASSWORD.toCharArray());
        Certificate certificate = primaryKeyStore.getCertificate(signingKeyAlias);
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(OAuth2Util.getKID(certificate, JWSAlgorithm.RS256, SUPER_TENANT))
                .build();
        JWTClaimsSet.Builder claimsSetBuilder = new JWTClaimsSet.Builder()
                .subject("admin")
                .issuer("https://localhost:9443/oauth2/token")
                .expirationTime(new Date(System.currentTimeMillis() + 3600 * 1000));
        if (withRealm) {
            claimsSetBuilder.claim(OAuthConstants.OIDCClaims.REALM,
                    Collections.singletonMap(OAuthConstants.OIDCClaims.SIGNING_TENANT, SUPER_TENANT));
        }
        SignedJWT signedJWT = new SignedJWT(header, claimsSetBuilder.build());
        signedJWT.sign(new RSASSASigner(privateKey));
        return signedJWT.serialize();
    }
}
