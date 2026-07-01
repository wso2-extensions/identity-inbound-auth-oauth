/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com) All Rights Reserved.
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
package org.wso2.carbon.identity.openidconnect;

import com.nimbusds.jwt.JWTClaimsSet;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.identity.claim.metadata.mgt.exception.ClaimMetadataException;
import org.wso2.carbon.identity.claim.metadata.mgt.model.ExternalClaim;
import org.wso2.carbon.identity.claim.metadata.mgt.model.LocalClaim;
import org.wso2.carbon.identity.claim.metadata.mgt.util.ClaimConstants;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.openidconnect.internal.OpenIDConnectServiceComponentHolder;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

/**
 * Tests selective multi-valued claim handling on the JWT/ID-token path
 * ({@link DefaultOIDCClaimsCallbackHandler}), gated by {@code ClaimMetadata.HonourMultiValued}.
 * Exercises the private {@code isMultiValuedAttribute} and {@code getMultiValuedClaimUris} methods.
 */
@WithCarbonHome
@Listeners(MockitoTestNGListener.class)
public class DefaultOIDCClaimsCallbackHandlerMultiValuedClaimTest {

    private static final String SEPARATOR = ",";
    private static final String TENANT_DOMAIN = "carbon.super";

    private static final String GIVEN_NAME = "given_name";
    private static final String MULTI_TEST = "multi_test";
    private static final String ADDRESS = "address";
    private static final String GROUPS = "groups";

    private static final String LOCAL_GIVEN_NAME_URI = "http://wso2.org/claims/givenname";
    private static final String LOCAL_MULTI_TEST_URI = "http://wso2.org/claims/multiTest";

    @Mock
    private ClaimMetadataManagementService claimMetadataManagementService;

    private DefaultOIDCClaimsCallbackHandler handler;
    private ClaimMetadataManagementService originalService;

    @BeforeMethod
    public void setUp() {

        handler = new DefaultOIDCClaimsCallbackHandler();
        // Preserve whatever (if anything) the holder already had so we don't pollute sibling tests.
        originalService = OpenIDConnectServiceComponentHolder.getInstance().getClaimMetadataManagementService();
    }

    @AfterMethod
    public void tearDown() {

        OpenIDConnectServiceComponentHolder.getInstance().setClaimMetadataManagementService(originalService);
    }

    /**
     * (a) Flag OFF: a {@code null} multi-valued set must preserve the legacy behaviour — a value
     * containing the separator is treated as multi-valued (array), a value without it is not.
     */
    @Test
    public void testLegacyBehaviourWhenFeatureDisabled() throws Exception {

        assertTrue(invokeIsMultiValued(GIVEN_NAME, "a,b,c,d", null),
                "Legacy path must split a comma-containing value into an array when the feature is off.");
        assertFalse(invokeIsMultiValued(GIVEN_NAME, "singleValue", null),
                "Legacy path must keep a value without the separator as a plain string.");
    }

    /**
     * (b) Flag ON + claim NOT flagged multi-valued: even though the value contains commas it must
     * be emitted as a plain string (not array).
     */
    @Test
    public void testSingleValuedClaimWithCommaRemainsStringWhenFeatureEnabled() throws Exception {

        Set<String> multiValued = new HashSet<>();
        multiValued.add(MULTI_TEST); // given_name is intentionally absent.
        assertFalse(invokeIsMultiValued(GIVEN_NAME, "a,b,c,d", multiValued),
                "A non-multi-valued claim with a comma value must stay a string when the feature is on.");
    }

    /**
     * (c) Flag ON + claim flagged multi-valued: emitted as an array.
     */
    @Test
    public void testMultiValuedClaimBecomesArrayWhenFeatureEnabled() throws Exception {

        Set<String> multiValued = new HashSet<>();
        multiValued.add(MULTI_TEST);
        assertTrue(invokeIsMultiValued(MULTI_TEST, "a,b,c,d", multiValued),
                "A claim flagged multi-valued must be emitted as an array when the feature is on.");
    }

    /**
     * (d) Special cases must be preserved regardless of the feature flag: {@code address} is never
     * an array (even with a separator) and {@code groups} is always an array.
     */
    @Test(dataProvider = "specialCaseProvider")
    public void testSpecialCaseClaimsPreserved(Set<String> multiValuedSet) throws Exception {

        assertFalse(invokeIsMultiValued(ADDRESS, "country,street,province", multiValuedSet),
                "address must never be treated as a multi-valued (array) attribute.");
        assertTrue(invokeIsMultiValued(GROUPS, "admin", multiValuedSet),
                "groups must always be treated as a multi-valued (array) attribute.");
    }

    @DataProvider(name = "specialCaseProvider")
    public Object[][] specialCaseProvider() {

        Set<String> enabledEmpty = new HashSet<>();           // feature on, nothing flagged.
        Set<String> enabledWithGroups = new HashSet<>();
        enabledWithGroups.add(GROUPS);
        return new Object[][]{
                {null},               // feature off (legacy).
                {enabledEmpty},       // feature on, groups/address not in set.
                {enabledWithGroups}
        };
    }

    /**
     * Resolving the metadata-derived set must return both the local claim URIs flagged {@code multiValued=true}
     * and their mapped OIDC claim URIs, so that preserved (non-OIDC) and OIDC-keyed claims both match.
     */
    @Test
    public void testGetMultiValuedClaimUrisResolvesFlaggedClaims() throws Exception {

        LocalClaim multiValuedLocal = new LocalClaim(LOCAL_MULTI_TEST_URI);
        multiValuedLocal.setClaimProperty(ClaimConstants.MULTI_VALUED_PROPERTY, "true");
        LocalClaim singleValuedLocal = new LocalClaim(LOCAL_GIVEN_NAME_URI);
        singleValuedLocal.setClaimProperty(ClaimConstants.MULTI_VALUED_PROPERTY, "false");

        ExternalClaim multiTestOidc =
                new ExternalClaim(OAuthConstants.OIDC_DIALECT, MULTI_TEST, LOCAL_MULTI_TEST_URI);
        ExternalClaim givenNameOidc =
                new ExternalClaim(OAuthConstants.OIDC_DIALECT, GIVEN_NAME, LOCAL_GIVEN_NAME_URI);

        when(claimMetadataManagementService.getLocalClaims(TENANT_DOMAIN))
                .thenReturn(Arrays.asList(multiValuedLocal, singleValuedLocal));
        when(claimMetadataManagementService.getExternalClaims(OAuthConstants.OIDC_DIALECT, TENANT_DOMAIN))
                .thenReturn(Arrays.asList(multiTestOidc, givenNameOidc));
        OpenIDConnectServiceComponentHolder.getInstance()
                .setClaimMetadataManagementService(claimMetadataManagementService);

        Set<String> resolved = invokeGetMultiValuedClaimUris(TENANT_DOMAIN);
        assertEquals(resolved, new HashSet<>(Arrays.asList(LOCAL_MULTI_TEST_URI, MULTI_TEST)),
                "Both the multiValued=true local claim URI and its mapped OIDC claim URI must be returned.");
    }

    /**
     * (e) Graceful fallback: when the claim metadata service is unavailable the method must return
     * {@code null} (legacy fallback) rather than fail token issuance.
     */
    @Test
    public void testGetMultiValuedClaimUrisReturnsNullWhenServiceUnavailable() throws Exception {

        OpenIDConnectServiceComponentHolder.getInstance().setClaimMetadataManagementService(null);
        assertNull(invokeGetMultiValuedClaimUris(TENANT_DOMAIN),
                "A missing claim metadata service must fall back to legacy handling (null set).");
    }

    /**
     * (e) Graceful fallback: a {@link ClaimMetadataException} during lookup must be swallowed and
     * mapped to {@code null} (legacy fallback), so token issuance never fails on metadata errors.
     */
    @Test
    public void testGetMultiValuedClaimUrisReturnsNullOnClaimMetadataException() throws Exception {

        when(claimMetadataManagementService.getLocalClaims(TENANT_DOMAIN))
                .thenThrow(new ClaimMetadataException("Simulated claim metadata failure."));
        OpenIDConnectServiceComponentHolder.getInstance()
                .setClaimMetadataManagementService(claimMetadataManagementService);

        assertNull(invokeGetMultiValuedClaimUris(TENANT_DOMAIN),
                "A ClaimMetadataException must be handled gracefully and fall back to legacy handling.");
    }

    /**
     * Exercises the handler wiring end to end: {@code setClaimsToJwtClaimSet} must read the feature flag, thread the
     * SP tenant domain into the metadata resolver and emit each claim with the correct type. With the flag ON a
     * multiValued-flagged claim is an array even for a single value, while a non-multiValued comma value stays a
     * string.
     */
    @Test
    public void testSetClaimsToJwtClaimSetEmitsArrayOnlyForMultiValuedWhenFeatureEnabled() throws Exception {

        stubClaimMetadata();
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put(MULTI_TEST, "solo");   // single value, flagged multiValued -> must be an array.
        claims.put(GIVEN_NAME, "a,b");    // not multiValued, has separator -> must stay a string.

        JWTClaimsSet result = invokeSetClaimsToJwtClaimSet(claims, TENANT_DOMAIN, true);

        assertTrue(result.getClaim(MULTI_TEST) instanceof List,
                "A multiValued-flagged claim must be an array even for a single value.");
        assertEquals(result.getClaim(MULTI_TEST), Collections.singletonList("solo"));
        assertTrue(result.getClaim(GIVEN_NAME) instanceof String,
                "A non-multiValued claim with a separator value must stay a string.");
        assertEquals(result.getClaim(GIVEN_NAME), "a,b");
    }

    /**
     * With the flag OFF the handler must keep the legacy separator-based behaviour: a value with the separator
     * becomes an array, a value without it stays a string.
     */
    @Test
    public void testSetClaimsToJwtClaimSetLegacyBehaviourWhenFeatureDisabled() throws Exception {

        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put(MULTI_TEST, "solo");   // no separator -> legacy keeps it a string.
        claims.put(GIVEN_NAME, "a,b");    // has separator -> legacy splits into an array.

        JWTClaimsSet result = invokeSetClaimsToJwtClaimSet(claims, TENANT_DOMAIN, false);

        assertTrue(result.getClaim(MULTI_TEST) instanceof String,
                "Legacy: a single value without the separator stays a string.");
        assertTrue(result.getClaim(GIVEN_NAME) instanceof List,
                "Legacy: a value containing the separator is split into an array.");
    }

    private void stubClaimMetadata() throws Exception {

        LocalClaim multiValuedLocal = new LocalClaim(LOCAL_MULTI_TEST_URI);
        multiValuedLocal.setClaimProperty(ClaimConstants.MULTI_VALUED_PROPERTY, "true");
        LocalClaim singleValuedLocal = new LocalClaim(LOCAL_GIVEN_NAME_URI);
        singleValuedLocal.setClaimProperty(ClaimConstants.MULTI_VALUED_PROPERTY, "false");
        ExternalClaim multiTestOidc =
                new ExternalClaim(OAuthConstants.OIDC_DIALECT, MULTI_TEST, LOCAL_MULTI_TEST_URI);
        ExternalClaim givenNameOidc =
                new ExternalClaim(OAuthConstants.OIDC_DIALECT, GIVEN_NAME, LOCAL_GIVEN_NAME_URI);
        when(claimMetadataManagementService.getLocalClaims(TENANT_DOMAIN))
                .thenReturn(Arrays.asList(multiValuedLocal, singleValuedLocal));
        when(claimMetadataManagementService.getExternalClaims(OAuthConstants.OIDC_DIALECT, TENANT_DOMAIN))
                .thenReturn(Arrays.asList(multiTestOidc, givenNameOidc));
        OpenIDConnectServiceComponentHolder.getInstance()
                .setClaimMetadataManagementService(claimMetadataManagementService);
    }

    private JWTClaimsSet invokeSetClaimsToJwtClaimSet(Map<String, Object> claims, String spTenantDomain,
                                                      boolean featureEnabled) throws Exception {

        // Toggle the field on the real configuration rather than mocking OAuthServerConfiguration statically:
        // OAuth2Util reads OAuthServerConfiguration.getInstance() in a static field initialiser, so a static mock
        // would poison its class initialisation.
        OAuthServerConfiguration config = OAuthServerConfiguration.getInstance();
        boolean original = config.getHonourMultiValuedClaimMetadata();
        setHonourMultiValuedClaimMetadata(config, featureEnabled);
        try (MockedStatic<FrameworkUtils> frameworkUtils = mockStatic(FrameworkUtils.class)) {
            frameworkUtils.when(FrameworkUtils::getMultiAttributeSeparator).thenReturn(SEPARATOR);
            Method method = DefaultOIDCClaimsCallbackHandler.class.getDeclaredMethod(
                    "setClaimsToJwtClaimSet", JWTClaimsSet.Builder.class, Map.class, String.class);
            method.setAccessible(true);
            return (JWTClaimsSet) method.invoke(handler, new JWTClaimsSet.Builder(), claims, spTenantDomain);
        } finally {
            setHonourMultiValuedClaimMetadata(config, original);
        }
    }

    private static void setHonourMultiValuedClaimMetadata(OAuthServerConfiguration config, boolean value)
            throws Exception {

        Field field = OAuthServerConfiguration.class.getDeclaredField("honourMultiValuedClaimMetadata");
        field.setAccessible(true);
        field.setBoolean(config, value);
    }

    private boolean invokeIsMultiValued(String claimKey, String claimValue, Set<String> multiValuedClaimUris) {

        // The predicate now lives in the shared OIDCClaimUtil; the handler delegates to it.
        return OIDCClaimUtil.isMultiValuedAttribute(claimKey, claimValue, SEPARATOR, multiValuedClaimUris);
    }

    @SuppressWarnings("unchecked")
    private Set<String> invokeGetMultiValuedClaimUris(String tenantDomain) throws Exception {

        Method method = DefaultOIDCClaimsCallbackHandler.class.getDeclaredMethod(
                "getMultiValuedClaimUris", String.class);
        method.setAccessible(true);
        return (Set<String>) method.invoke(handler, tenantDomain);
    }
}
