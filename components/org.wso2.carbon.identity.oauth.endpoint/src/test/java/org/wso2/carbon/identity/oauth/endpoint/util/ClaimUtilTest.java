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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.oauth.endpoint.util;

import org.apache.commons.collections.map.HashedMap;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.Claim;
import org.wso2.carbon.identity.application.common.model.ClaimConfig;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.LocalAndOutboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.LocalRole;
import org.wso2.carbon.identity.application.common.model.PermissionsAndRoleConfig;
import org.wso2.carbon.identity.application.common.model.RoleMapping;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataHandler;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.user.UserInfoEndpointException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.isNull;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;

@PrepareForTest ( {IdentityTenantUtil.class, OAuth2Util.class, OAuthServerConfiguration.class,
        OAuth2ServiceComponentHolder.class, ClaimMetadataHandler.class, IdentityUtil.class})
public class ClaimUtilTest extends PowerMockIdentityBaseTest {

    @Mock
    private OAuth2TokenValidationResponseDTO mockedValidationTokenResponseDTO;

    @Mock
    private UserRealm mockedUserRealm;

    @Mock
    private OAuthServerConfiguration mockedOAuthServerConfiguration;

    @Mock
    private UserStoreManager mockedUserStoreManager;

    @Mock
    private ApplicationManagementService mockedApplicationManagementService;

    @Mock
    private ServiceProvider mockedServiceProvider;

    @Mock
    private OAuth2TokenValidationResponseDTO.AuthorizationContextToken mockedAuthzContextToken;

    @Mock
    private ClaimConfig mockedClaimConfig;

    @Mock
    private LocalAndOutboundAuthenticationConfig mockedLocalAndOutboundConfig;

    @Mock
    private ClaimMetadataHandler mockedClaimMetadataHandler;

    @Mock
    private OAuthAppDO mockedOAuthAppDO;

    @Mock
    private RealmConfiguration mockedRealmConfiguration;

    @Mock
    private PermissionsAndRoleConfig mockedPermissionAndRoleConfig;


    private Field claimUtilLogField;
    private Object claimUtilObject;

    private RoleMapping[] roleMappings;

    private ClaimMapping[] requestedClaimMappings;

    private Map<String, String> userClaimsMap;

    private Map<Object, Object> spToLocalClaimMappings;

    private Map userClaimsMapWithSubject;

    private static final String AUTHORIZED_USER = "authUser";
    private static final String CLIENT_ID = "myClientID12345";
    private static final String CLAIM_SEPARATOR = ",";
    private static final String USERNAME_CLAIM_URI = "http://wso2.org/claims/username";
    private static final String EMAIL_CLAIM_URI = "http://wso2.org/claims/emailaddress";
    private static final String ROLE_CLAIM_URI = "http://wso2.org/claims/role";

    @BeforeClass
    public void setup() {

        //Setting requested claims in SP
        requestedClaimMappings = new ClaimMapping[3];

        ClaimMapping claimMapping1 = new ClaimMapping();
        ClaimMapping claimMapping2 = new ClaimMapping();
        ClaimMapping claimMapping3 = new ClaimMapping();
        Claim claim1 = new Claim();
        Claim claim2 = new Claim();
        Claim claim3 = new Claim();

        claim1.setClaimUri(USERNAME_CLAIM_URI);
        claimMapping1.setLocalClaim(claim1);
        claimMapping1.setRemoteClaim(claim1);
        requestedClaimMappings[0] = claimMapping1;

        claim2.setClaimUri(ROLE_CLAIM_URI);
        claimMapping2.setLocalClaim(claim2);
        claimMapping2.setRemoteClaim(claim2);
        requestedClaimMappings[1] = claimMapping2;

        claim3.setClaimUri(EMAIL_CLAIM_URI);
        claimMapping3.setLocalClaim(claim3);
        claimMapping3.setRemoteClaim(claim3);
        claimMapping3.setRequested(true);
        requestedClaimMappings[2] = claimMapping3;

        //Setting returning claims from user store
        userClaimsMap = new HashMap<>();
        userClaimsMap.put(USERNAME_CLAIM_URI, AUTHORIZED_USER);
        userClaimsMap.put(EMAIL_CLAIM_URI, "test@wso2.com");
        userClaimsMap.put(ROLE_CLAIM_URI, "role1");

        userClaimsMapWithSubject = new HashedMap();
        userClaimsMap.put(USERNAME_CLAIM_URI, AUTHORIZED_USER);

        //Setting SP to local claim mapping
        spToLocalClaimMappings = new HashMap<>();
        spToLocalClaimMappings.put(USERNAME_CLAIM_URI, USERNAME_CLAIM_URI);
        spToLocalClaimMappings.put(ROLE_CLAIM_URI, ROLE_CLAIM_URI);
        spToLocalClaimMappings.put(EMAIL_CLAIM_URI, EMAIL_CLAIM_URI);

        //Setting SP role mappings
        roleMappings = new RoleMapping[2];
        LocalRole role1 = new LocalRole("PRIMARY", "role1");
        LocalRole role2 = new LocalRole("PRIMARY", "role2");

        RoleMapping mapping1 = new RoleMapping(role1, "remoteRole1");
        RoleMapping mapping2 = new RoleMapping(role2, "remoteRole2");

        roleMappings[0] = mapping1;
        roleMappings[1] = mapping2;
    }

    @DataProvider(name = "provideDataForGetClaimsFromUser")
    public Object[][] provideDataForGetClaimsFromUser() {
        return new Object[][] {
                // TODO: Realm is NULL
//                { false, true, true, requestedClaimMappings, spToLocalClaimMappings, userClaimsMap, CLIENT_ID,
//                        USERNAME_CLAIM_URI, "PRIMARY", CLAIM_SEPARATOR, false, false,, 1},
                { true, false, true, requestedClaimMappings, spToLocalClaimMappings, userClaimsMap, CLIENT_ID,
                        USERNAME_CLAIM_URI, "PRIMARY", CLAIM_SEPARATOR, false, false, -1},
                // TODO: SP NULL
//                { true, true, false, requestedClaimMappings, spToLocalClaimMappings, userClaimsMap, CLIENT_ID,
//                        USERNAME_CLAIM_URI, "PRIMARY", CLAIM_SEPARATOR, false, false, 1},
                { true, true, true, new ClaimMapping[0], spToLocalClaimMappings, userClaimsMapWithSubject, CLIENT_ID,
                        USERNAME_CLAIM_URI, "PRIMARY", CLAIM_SEPARATOR, false, false, 1},
                { true, true, true, requestedClaimMappings, new HashMap<String, String>(), userClaimsMap, CLIENT_ID,
                        USERNAME_CLAIM_URI, "PRIMARY", CLAIM_SEPARATOR, false, false, 1},
                { true, true, true, requestedClaimMappings, spToLocalClaimMappings, new HashMap<String, String>(),
                        CLIENT_ID, null, "PRIMARY", CLAIM_SEPARATOR, false, false, 1},
                { true, true, true, requestedClaimMappings, spToLocalClaimMappings, userClaimsMap, CLIENT_ID,
                        EMAIL_CLAIM_URI, "PRIMARY", CLAIM_SEPARATOR, false, false, 4},
                { true, true, true, null, spToLocalClaimMappings, userClaimsMapWithSubject, CLIENT_ID, null, "PRIMARY",
                        CLAIM_SEPARATOR, false, false, 1},
                { true, true, true, new ClaimMapping[0], spToLocalClaimMappings, userClaimsMap, CLIENT_ID, null,
                        "PRIMARY", CLAIM_SEPARATOR, false, false, 1},
                { true, true, true, requestedClaimMappings, spToLocalClaimMappings, userClaimsMap, CLIENT_ID,
                        USERNAME_CLAIM_URI, "", CLAIM_SEPARATOR, false, false, 3},
                { true, true, true, requestedClaimMappings, spToLocalClaimMappings, userClaimsMap, CLIENT_ID,
                        USERNAME_CLAIM_URI, "FEDERATED_UM", CLAIM_SEPARATOR, false, false, 1},
                { true, true, true, requestedClaimMappings, spToLocalClaimMappings, userClaimsMap, CLIENT_ID,
                        USERNAME_CLAIM_URI, "PRIMARY", "", false, false, 3},
                { true, true, true, requestedClaimMappings, spToLocalClaimMappings, userClaimsMap, CLIENT_ID,
                        USERNAME_CLAIM_URI, "PRIMARY", CLAIM_SEPARATOR, true, false, 1},
                { true, true, true, requestedClaimMappings, spToLocalClaimMappings, userClaimsMap, CLIENT_ID,
                        USERNAME_CLAIM_URI, "PRIMARY", CLAIM_SEPARATOR, false, true, 3},
                { true, true, true, requestedClaimMappings, spToLocalClaimMappings, userClaimsMap, CLIENT_ID,
                        USERNAME_CLAIM_URI, "PRIMARY", CLAIM_SEPARATOR, false, false, 3},
                { true, true, true, requestedClaimMappings, spToLocalClaimMappings, userClaimsMap, CLIENT_ID,
                        USERNAME_CLAIM_URI, "FEDERATED_UM", CLAIM_SEPARATOR, false, false, 1},
                    // TODO : Userstore exception
//                { true, true, true, requestedClaimMappings, spToLocalClaimMappings, null, CLIENT_ID,
//                        USERNAME_CLAIM_URI, "PRIMARY", CLAIM_SEPARATOR, false, false, 0},

        };

    }

    @Test(dataProvider = "provideDataForGetClaimsFromUser")
    public void testGetClaimsFromUserStore(boolean mockRealm, boolean mockAccessTokenDO, boolean mockServiceProvider,
                                           Object claimMappingObject, Map<String, String> spToLocalClaimMappings,
                                           Map<String, String> userClaimsMap, String clientId, String subjectClaimUri,
                                           String userStoreDomain, String claimSeparator, boolean isFederated,
                                           boolean mapFedUsersToLocal, int expectedMapSize) throws  Exception {

        ClaimMapping[] claimMappings = (ClaimMapping[]) claimMappingObject;
        mockStatic(IdentityTenantUtil.class);
        if (mockRealm) {
            when(IdentityTenantUtil.getRealm(anyString(), anyString())).thenReturn(mockedUserRealm);
        } else {
            when(IdentityTenantUtil.getRealm(anyString(), anyString())).thenReturn(null);
        }

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedOAuthServerConfiguration);
        when(mockedOAuthServerConfiguration.isMapFederatedUsersToLocal()).thenReturn(mapFedUsersToLocal);

        mockOAuth2Util();

        AccessTokenDO accessTokenDO = getAccessTokenDO(clientId, userStoreDomain, isFederated);
        if (mockAccessTokenDO) {
            when(OAuth2Util.getAccessTokenDOfromTokenIdentifier(anyString())).thenReturn(accessTokenDO);
        }

        mockStatic(OAuth2ServiceComponentHolder.class);
        when(OAuth2ServiceComponentHolder.getApplicationMgtService()).thenReturn(mockedApplicationManagementService);
        when(mockedApplicationManagementService.getServiceProviderNameByClientId(
                anyString(), anyString(), anyString())).thenReturn("SP1");

        if (mockServiceProvider) {
            when(mockedApplicationManagementService.getApplicationExcludingFileBasedSPs(anyString(), anyString())).
                    thenReturn(mockedServiceProvider);
        }


        when(mockedValidationTokenResponseDTO.getAuthorizedUser()).thenReturn(AUTHORIZED_USER);
        when(mockedValidationTokenResponseDTO.getAuthorizationContextToken()).thenReturn(mockedAuthzContextToken);
        when(mockedUserRealm.getUserStoreManager()).thenReturn(mockedUserStoreManager);

        when(mockedServiceProvider.getClaimConfig()).thenReturn(mockedClaimConfig);
        when(mockedClaimConfig.getClaimMappings()).thenReturn(claimMappings);

        when(mockedServiceProvider.getLocalAndOutBoundAuthenticationConfig()).thenReturn(mockedLocalAndOutboundConfig);
        when(mockedLocalAndOutboundConfig.getSubjectClaimUri()).thenReturn(subjectClaimUri);

        mockStatic(ClaimMetadataHandler.class);
        when(ClaimMetadataHandler.getInstance()).thenReturn(mockedClaimMetadataHandler);
        when(mockedClaimMetadataHandler.getMappingsMapFromOtherDialectToCarbon(
                anyString(), isNull(Set.class), anyString(), anyBoolean())).thenReturn(spToLocalClaimMappings);

        if (userClaimsMap != null) {
            when(mockedUserStoreManager.getUserClaimValues(anyString(), any(String[].class), anyString())).
                    thenReturn(userClaimsMap);
        } else {
            when(mockedUserStoreManager.getUserClaimValues(anyString(), any(String[].class), anyString())).
                    thenThrow(new UserStoreException("UserNotFound"));
        }

        mockStatic(IdentityUtil.class);
        when(IdentityUtil.extractDomainFromName(anyString())).thenReturn(userStoreDomain);

        when(mockedUserRealm.getUserStoreManager()).thenReturn(mockedUserStoreManager);
        when(mockedUserStoreManager.getSecondaryUserStoreManager(anyString())).thenReturn(mockedUserStoreManager);
        when(mockedUserStoreManager.getRealmConfiguration()).thenReturn(mockedRealmConfiguration);
        when(mockedRealmConfiguration.getUserStoreProperty(
                IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR)).thenReturn(claimSeparator);

        when(mockedServiceProvider.getPermissionAndRoleConfig()).thenReturn(mockedPermissionAndRoleConfig);
        when(mockedPermissionAndRoleConfig.getRoleMappings()).thenReturn(roleMappings);

        Map<String, Object> claimsMap;
        try {
            claimsMap = ClaimUtil.getClaimsFromUserStore(mockedValidationTokenResponseDTO);
            Assert.assertEquals(claimsMap.size(), expectedMapSize);
        } catch (UserInfoEndpointException e) {
            Assert.assertEquals(expectedMapSize, -1, "Unexpected exception thrown");
        }
    }

    protected void mockOAuth2Util() throws IdentityOAuth2Exception, InvalidOAuthClientException {
        mockStatic(OAuth2Util.class);
        when(OAuth2Util.getAuthenticatedUser(any(AccessTokenDO.class))).thenCallRealMethod();
        when(OAuth2Util.isFederatedUser(any(AuthenticatedUser.class))).thenCallRealMethod();
        when(OAuth2Util.getAppInformationByClientId(anyString())).thenReturn(mockedOAuthAppDO);
        when(OAuth2Util.getTenantDomainOfOauthApp(any(OAuthAppDO.class))).thenReturn("carbon.super");
    }

    private AccessTokenDO getAccessTokenDO(String clientId, String userStoreDomain, boolean isFederated) {
        AuthenticatedUser authenticatedUser = getAuthenticatedUser(userStoreDomain, isFederated);
        AccessTokenDO accessTokenDO = new AccessTokenDO();
        accessTokenDO.setConsumerKey(clientId);
        accessTokenDO.setAuthzUser(authenticatedUser);
        return accessTokenDO;
    }

    private AuthenticatedUser getAuthenticatedUser(String userStoreDomain, boolean isFederated) {
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserStoreDomain(userStoreDomain);
        authenticatedUser.setFederatedUser(isFederated);
        return authenticatedUser;
    }

    @DataProvider(name = "provideRoleMappingData")
    public Object[][] provideRoleMappingData() {

        return new Object[][] {
                {new ArrayList<String>(), roleMappings,  ",", null},
                {null, null,  ",", null},
                {new ArrayList<String>(){{add("role1"); add("role2"); }}, null,  ",,,", "role1,,,role2"},
                {new ArrayList<String>(){{add("role1"); add("role2");}}, roleMappings, "#", "remoteRole1#remoteRole2"},
                {new ArrayList<String>(){{add("role1"); }}, new RoleMapping[0], "," , "role1"}
        };
    }

    @Test (dataProvider = "provideRoleMappingData")
    public void testGetServiceProviderMappedUserRoles(List<String> locallyMappedUserRoles,
                                                      Object roleMappingObject,
                                                      String claimSeparator,
                                                      String expected)  throws Exception {

        RoleMapping[] roleMappings = (RoleMapping[]) roleMappingObject;
        when(mockedServiceProvider.getPermissionAndRoleConfig()).thenReturn(mockedPermissionAndRoleConfig);
        when(mockedPermissionAndRoleConfig.getRoleMappings()).thenReturn(roleMappings);
        String returned = ClaimUtil.getServiceProviderMappedUserRoles(mockedServiceProvider,
                locallyMappedUserRoles, claimSeparator);
        Assert.assertEquals(returned, expected, "Invalid returned value");
    }
}
