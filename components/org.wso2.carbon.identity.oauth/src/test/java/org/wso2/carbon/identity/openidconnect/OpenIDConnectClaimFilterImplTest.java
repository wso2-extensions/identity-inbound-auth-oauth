/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.impl.consent.ClaimMetaData;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.impl.consent.SSOConsentService;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.impl.consent.SSOConsentServiceImpl;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.identity.claim.metadata.mgt.model.ExternalClaim;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.common.testng.WithRegistry;
import org.wso2.carbon.identity.oauth.dto.ScopeDTO;
import org.wso2.carbon.identity.oauth2.TestConstants;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.openidconnect.cache.OIDCScopeClaimCache;
import org.wso2.carbon.identity.openidconnect.cache.OIDCScopeClaimCacheEntry;
import org.wso2.carbon.identity.openidconnect.internal.OpenIDConnectServiceComponentHolder;
import org.wso2.carbon.identity.openidconnect.model.RequestedClaim;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;

@WithCarbonHome
@WithRegistry
@WithRealmService
@WithH2Database(files = {"dbScripts/identity.sql", "dbScripts/insert_scope_claim.sql"})
public class OpenIDConnectClaimFilterImplTest {

    private static final String SP_TENANT_DOMAIN = "carbon.super";
    private static final String CLIENT_ID = TestConstants.CLIENT_ID;

    private OpenIDConnectClaimFilterImpl openIDConnectClaimFilter;
    private ApplicationManagementService applicationMgtService;
    SSOConsentService ssoConsentService;
    private Set<String> requestedScopes;
    private List  scopeDTOList;
    private Map<String, Object> claims;

    @BeforeClass
    public void setUp() throws Exception {

        openIDConnectClaimFilter = new OpenIDConnectClaimFilterImpl();
        ServiceProvider serviceProvider = new ServiceProvider();
        ssoConsentService = mock(SSOConsentServiceImpl.class);
        ClaimMetadataManagementService claimMetadataManagementService =
                mock(ClaimMetadataManagementService.class);
        applicationMgtService = mock(ApplicationManagementService.class);
        OAuth2ServiceComponentHolder.setApplicationMgtService(applicationMgtService);
        when(applicationMgtService
                .getServiceProviderByClientId(CLIENT_ID, IdentityApplicationConstants.OAuth2.NAME,
                        SP_TENANT_DOMAIN))
                .thenReturn(serviceProvider);
        OpenIDConnectServiceComponentHolder.getInstance()
                .setClaimMetadataManagementService(claimMetadataManagementService);
        OpenIDConnectServiceComponentHolder.getInstance().setSsoConsentService(ssoConsentService);

        List externalClaims = new ArrayList<>();
        ExternalClaim externalClaim = new ExternalClaim("testUserClaimURI",
                "testUserClaimURI", "testUserClaimURI");
        externalClaims.add(externalClaim);
        when(claimMetadataManagementService.getExternalClaims(anyString(), anyString()))
                .thenReturn(externalClaims);
        List claimsWithConsent = getClaimsWithConsent();
        when(ssoConsentService.getClaimsWithConsents(any(), any())).thenReturn(claimsWithConsent);

    }

    @Test
    public void testGetPriority() {

        Assert.assertEquals(openIDConnectClaimFilter.getPriority(), 100);
    }

    @DataProvider(name = "testGetClaimsFilteredByOIDCScopes")
    public Object[][] getClaimsFilteredByOIDCScopes() {

        return new Object[][] {
                {"email", 2, "claim1"},
                {"address", 1, "claim3"}
        };
    }

    @Test(dataProvider = "testGetClaimsFilteredByOIDCScopes")
    public void testGetClaimsFilteredByOIDCScopes(String requestedScope, int numberOfClaims,
                                                  String claim) throws Exception {

        requestedScopes = new HashSet<>();
        requestedScopes.add(requestedScope);
        OIDCScopeClaimCacheEntry oidcScopeClaimCacheEntry = new OIDCScopeClaimCacheEntry();
        oidcScopeClaimCacheEntry.setScopeClaimMapping(getScopeDTOList());
        OIDCScopeClaimCache.getInstance().addScopeClaimMap(-1234, oidcScopeClaimCacheEntry);
        List claims = openIDConnectClaimFilter.getClaimsFilteredByOIDCScopes(requestedScopes, SP_TENANT_DOMAIN);
        Assert.assertEquals(claims.size(), numberOfClaims);
        Assert.assertEquals(claims.get(0), claim);
    }

    @Test
    public void testHandleUpdatedAtClaim() {

        String date = "2021-10-27T11:34:13.791Z";
        claims = new HashMap<>();
        claims.put("updated_at", date);
        String[] requestedScopes = {"profile"};
        OIDCScopeClaimCacheEntry oidcScopeClaimCacheEntry = new OIDCScopeClaimCacheEntry();
        oidcScopeClaimCacheEntry.setScopeClaimMapping(getScopeDTOList());
        OIDCScopeClaimCache.getInstance().addScopeClaimMap(-1234, oidcScopeClaimCacheEntry);
        Map<String, Object> filteredClaims = openIDConnectClaimFilter.getClaimsFilteredByOIDCScopes(claims,
                requestedScopes, CLIENT_ID, SP_TENANT_DOMAIN);
        // Due to the effect of time zone during time conversion, considering only the seconds during comparison
        // Check is to ensure this claim is in seconds not milliseconds
        String filteredDate = String.valueOf(filteredClaims.get("updated_at"));
        Assert.assertEquals(filteredDate.substring(8), "53");
    }

    @Test
    public void testGetClaimsFilteredByUserConsent() throws Exception {

        claims = getClaims();
        AuthenticatedUser user = getDefaultAuthenticatedLocalUser();
        when(ssoConsentService.isSSOConsentManagementEnabled(any())).thenReturn(true);
        OIDCScopeClaimCacheEntry oidcScopeClaimCacheEntry = new OIDCScopeClaimCacheEntry();
        oidcScopeClaimCacheEntry.setScopeClaimMapping(getScopeDTOList());
        OIDCScopeClaimCache.getInstance().addScopeClaimMap(-1234, oidcScopeClaimCacheEntry);
        Map<String, Object> claimFilter = openIDConnectClaimFilter
                .getClaimsFilteredByUserConsent(claims, user, CLIENT_ID, SP_TENANT_DOMAIN);
        Assert.assertEquals(((ScopeDTO) claimFilter.get("testUserClaimURI")).getName(), "email");
        Assert.assertEquals(((ScopeDTO) claimFilter.get("testUserClaimURI"))
                .getDescription(), "emailDescription");
        Assert.assertNull(claimFilter.get("testUserClaimURI2"));
    }

    @Test
    public void testGetClaimsFilteredByUserConsentWithManagementServiceDisabled() throws Exception {

        claims = getClaims();
        AuthenticatedUser user = getDefaultAuthenticatedLocalUser();
        when(ssoConsentService.isSSOConsentManagementEnabled(any())).thenReturn(false);
        Map<String, Object> claimFilter = openIDConnectClaimFilter
                .getClaimsFilteredByUserConsent(claims, user, CLIENT_ID, SP_TENANT_DOMAIN);
        Assert.assertEquals(((ScopeDTO) claimFilter.get("testUserClaimURI")).getName(),
                "email");
        Assert.assertEquals(((ScopeDTO) claimFilter.get("testUserClaimURI"))
                .getDescription(), "emailDescription");
        Assert.assertEquals(((ScopeDTO) claimFilter.get("testUserClaimURI2")).getName(),
                "address");
        Assert.assertEquals(((ScopeDTO) claimFilter.get("testUserClaimURI2"))
                .getDescription(), "addressDescription");
    }

    @Test
    public void testGetClaimsFilteredByEssentialClaimsWithValues() throws Exception {

        claims = new HashMap<>();
        claims.put("testUserClaimURI", "value1");
        claims.put("testUserClaimURI2", "value2");
        List requestedClaims = new ArrayList<>();
        RequestedClaim requestedClaim = new RequestedClaim();
        requestedClaim.setName("testUserClaimURI");
        requestedClaim.setEssential(true);
        List values = new ArrayList();
        values.add("value1");
        requestedClaim.setValues(values);
        requestedClaims.add(requestedClaim);
        Map<String, Object> filteredClaims = openIDConnectClaimFilter
                .getClaimsFilteredByEssentialClaims(claims, requestedClaims);
        Assert.assertNotNull(filteredClaims.get("testUserClaimURI"));
        Assert.assertNull(filteredClaims.get("testUserClaimURI2"));
        Assert.assertEquals(((String) filteredClaims.get("testUserClaimURI")), "value1");
    }

    @Test
    public void testGetClaimsFilteredByEssentialClaimsWithValue() throws Exception {

        claims = new HashMap<>();
        claims.put("testUserClaimURI", "value1");
        claims.put("testUserClaimURI2", "value2");
        List requestedClaims = new ArrayList<>();
        RequestedClaim requestedClaim = new RequestedClaim();
        requestedClaim.setName("testUserClaimURI");
        requestedClaim.setEssential(true);
        requestedClaim.setValue("value1");
        requestedClaims.add(requestedClaim);
        Map<String, Object> filteredClaims = openIDConnectClaimFilter
                .getClaimsFilteredByEssentialClaims(claims, requestedClaims);
        Assert.assertEquals(filteredClaims.size(), 1);

    }

    @Test
    public void testGetClaimsFilteredByEssentialClaimsWithNullValue() throws Exception {

        claims = new HashMap<>();
        claims.put("testUserClaimURI", "value1");
        claims.put("testUserClaimURI2", "value2");
        List requestedClaims = new ArrayList<>();
        RequestedClaim requestedClaim = new RequestedClaim();
        requestedClaim.setName("testUserClaimURI");
        requestedClaim.setEssential(true);
        requestedClaims.add(requestedClaim);
        Map<String, Object> filteredClaims = openIDConnectClaimFilter
                .getClaimsFilteredByEssentialClaims(claims, requestedClaims);
        Assert.assertNotNull(filteredClaims.get("testUserClaimURI"));
        Assert.assertNull(filteredClaims.get("testUserClaimURI2"));
        Assert.assertEquals(((String) filteredClaims.get("testUserClaimURI")), "value1");
    }

    @Test
    public void testGetClaimsFilteredByUserConsentWithException() throws Exception {

        claims = getClaims();
        AuthenticatedUser user = getDefaultAuthenticatedLocalUser();
        when(ssoConsentService.isSSOConsentManagementEnabled(any())).thenReturn(false);
        Mockito.doThrow(new IdentityApplicationManagementException("")).when(applicationMgtService)
                .getServiceProviderByClientId("dummy", IdentityApplicationConstants.OAuth2.NAME,
                        SP_TENANT_DOMAIN);
        Map<String, Object> claimFilter = openIDConnectClaimFilter
                .getClaimsFilteredByUserConsent(claims, user, "dummy", SP_TENANT_DOMAIN);
        Assert.assertEquals(((ScopeDTO) claimFilter.get("testUserClaimURI")).getName(),
                "email");
        Assert.assertEquals(((ScopeDTO) claimFilter.get("testUserClaimURI"))
                .getDescription(), "emailDescription");
        Assert.assertEquals(((ScopeDTO) claimFilter.get("testUserClaimURI2")).getName(),
                "address");
        Assert.assertEquals(((ScopeDTO) claimFilter.get("testUserClaimURI2"))
                .getDescription(), "addressDescription");

    }

    private List<ScopeDTO> getScopeDTOList() {

        ScopeDTO scopeDTOForEmail = new ScopeDTO();
        scopeDTOForEmail.setName("email");
        scopeDTOForEmail.setDisplayName("emailDisplayName");
        scopeDTOForEmail.setDescription("emailDescription");
        String[] claimsForEmail = new String[]{"claim1", "claim2"};
        scopeDTOForEmail.setClaim(claimsForEmail);

        ScopeDTO scopeDTOForAddress = new ScopeDTO();
        scopeDTOForAddress.setName("address");
        scopeDTOForAddress.setDisplayName("addressDisplayName");
        scopeDTOForAddress.setDescription("addressDescription");
        String[] claimsForAddress = new String[]{"claim3"};
        scopeDTOForAddress.setClaim(claimsForAddress);

        ScopeDTO scopeDTOForProfile = new ScopeDTO();
        scopeDTOForProfile.setName("profile");
        scopeDTOForProfile.setDisplayName("profileDisplayName");
        scopeDTOForProfile.setDescription("profileDescription");
        String[] claimsForProfile = new String[]{"updated_at"};
        scopeDTOForProfile.setClaim(claimsForProfile);

        scopeDTOList = new ArrayList<>();
        scopeDTOList.add(scopeDTOForEmail);
        scopeDTOList.add(scopeDTOForAddress);
        scopeDTOList.add(scopeDTOForProfile);
        return scopeDTOList;
    }

    private AuthenticatedUser getDefaultAuthenticatedLocalUser() {

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier(org.wso2.carbon.identity.oauth2.TestConstants.USER_NAME);
        authenticatedUser.setUserName(org.wso2.carbon.identity.oauth2.TestConstants.USER_NAME);
        authenticatedUser.setUserStoreDomain(TestConstants.USER_STORE_DOMAIN);
        authenticatedUser.setTenantDomain(SUPER_TENANT_DOMAIN_NAME);
        authenticatedUser.setFederatedUser(false);
        return authenticatedUser;
    }

    private List<ClaimMetaData> getClaimsWithConsent() {

        List<ClaimMetaData> claimsWithConsent = new ArrayList<>();
        ClaimMetaData claimMetaData = new ClaimMetaData();
        claimMetaData.setId(1);
        claimMetaData.setClaimUri("testUserClaimURI");
        claimMetaData.setDisplayName("claimMetaData");
        claimMetaData.setDescription("claimMetaDataDescription");
        claimsWithConsent.add(claimMetaData);
        return claimsWithConsent;
    }

    private Map<String, Object> getClaims() {
        Map<String, Object> claims = new HashMap<>();
        List scopeDTOList = getScopeDTOList();
        claims.put("testUserClaimURI", scopeDTOList.get(0));
        claims.put("testUserClaimURI2", scopeDTOList.get(1));
        return claims;
    }
}
