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
import org.mockito.MockedStatic;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.AssociatedRolesConfig;
import org.wso2.carbon.identity.application.common.model.Claim;
import org.wso2.carbon.identity.application.common.model.ClaimConfig;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.LocalAndOutboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.LocalRole;
import org.wso2.carbon.identity.application.common.model.PermissionsAndRoleConfig;
import org.wso2.carbon.identity.application.common.model.RoleMapping;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.model.ServiceProviderProperty;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataHandler;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.tokenprocessor.DefaultTokenProvider;
import org.wso2.carbon.identity.oauth.user.UserInfoEndpointException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.role.v2.mgt.core.RoleConstants;
import org.wso2.carbon.identity.role.v2.mgt.core.RoleManagementService;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.wso2.carbon.identity.application.mgt.ApplicationConstants.IS_FRAGMENT_APP;

@Listeners(MockitoTestNGListener.class)
public class ClaimUtilTest {

    @Mock
    private OAuth2TokenValidationResponseDTO mockedValidationTokenResponseDTO;

    @Mock
    private UserRealm mockedUserRealm;

    @Mock
    private OAuthServerConfiguration mockedOAuthServerConfiguration;

    private AbstractUserStoreManager mockedUserStoreManager;

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

    @Mock
    private RoleManagementService mockedRoleManagementService;

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

        return new Object[][]{
                // TODO: Realm is NULL
//                { false, true, true, requestedClaimMappings, spToLocalClaimMappings, userClaimsMap, CLIENT_ID,
//                        USERNAME_CLAIM_URI, "PRIMARY", CLAIM_SEPARATOR, false, false,, 1},
                {true, false, true, requestedClaimMappings, spToLocalClaimMappings, userClaimsMap, CLIENT_ID,
                        USERNAME_CLAIM_URI, "PRIMARY", CLAIM_SEPARATOR, false, false, -1},
                // TODO: SP NULL
//                { true, true, false, requestedClaimMappings, spToLocalClaimMappings, userClaimsMap, CLIENT_ID,
//                        USERNAME_CLAIM_URI, "PRIMARY", CLAIM_SEPARATOR, false, false, 1},
                {true, true, true, new ClaimMapping[0], spToLocalClaimMappings, userClaimsMapWithSubject, CLIENT_ID,
                        USERNAME_CLAIM_URI, "PRIMARY", CLAIM_SEPARATOR, false, false, 1},
                {true, true, true, requestedClaimMappings, new HashMap<String, String>(), userClaimsMap, CLIENT_ID,
                        USERNAME_CLAIM_URI, "PRIMARY", CLAIM_SEPARATOR, false, false, 1},
                {true, true, true, requestedClaimMappings, spToLocalClaimMappings, new HashMap<String, String>(),
                        CLIENT_ID, null, "PRIMARY", CLAIM_SEPARATOR, false, false, 1},
                {true, true, true, requestedClaimMappings, spToLocalClaimMappings, userClaimsMap, CLIENT_ID,
                        EMAIL_CLAIM_URI, "PRIMARY", CLAIM_SEPARATOR, false, false, 4},
                {true, true, true, null, spToLocalClaimMappings, userClaimsMapWithSubject, CLIENT_ID, null, "PRIMARY",
                        CLAIM_SEPARATOR, false, false, 1},
                {true, true, true, new ClaimMapping[0], spToLocalClaimMappings, userClaimsMap, CLIENT_ID, null,
                        "PRIMARY", CLAIM_SEPARATOR, false, false, 1},
                {true, true, true, requestedClaimMappings, spToLocalClaimMappings, userClaimsMap, CLIENT_ID,
                        USERNAME_CLAIM_URI, "", CLAIM_SEPARATOR, false, false, 3},
                {true, true, true, requestedClaimMappings, spToLocalClaimMappings, userClaimsMap, CLIENT_ID,
                        USERNAME_CLAIM_URI, "FEDERATED_UM", CLAIM_SEPARATOR, false, false, 1},
                {true, true, true, requestedClaimMappings, spToLocalClaimMappings, userClaimsMap, CLIENT_ID,
                        USERNAME_CLAIM_URI, "PRIMARY", "", false, false, 3},
                {true, true, true, requestedClaimMappings, spToLocalClaimMappings, userClaimsMap, CLIENT_ID,
                        USERNAME_CLAIM_URI, "PRIMARY", CLAIM_SEPARATOR, true, false, 1},
                {true, true, true, requestedClaimMappings, spToLocalClaimMappings, userClaimsMap, CLIENT_ID,
                        USERNAME_CLAIM_URI, "PRIMARY", CLAIM_SEPARATOR, false, true, 3},
                {true, true, true, requestedClaimMappings, spToLocalClaimMappings, userClaimsMap, CLIENT_ID,
                        USERNAME_CLAIM_URI, "PRIMARY", CLAIM_SEPARATOR, false, false, 3},
                {true, true, true, requestedClaimMappings, spToLocalClaimMappings, userClaimsMap, CLIENT_ID,
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
                                           boolean mapFedUsersToLocal, int expectedMapSize) throws Exception {

        try (MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                     OAuthServerConfiguration.class);
             MockedStatic<FrameworkUtils> frameworkUtils = mockStatic(FrameworkUtils.class);
             MockedStatic<OAuth2ServiceComponentHolder> oAuth2ServiceComponentHolder =
                     mockStatic(OAuth2ServiceComponentHolder.class);
             MockedStatic<ClaimMetadataHandler> claimMetadataHandler =
                     mockStatic(ClaimMetadataHandler.class);
             MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {

            oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance)
                    .thenReturn(mockedOAuthServerConfiguration);

            try (MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class)) {

                ClaimMapping[] claimMappings = (ClaimMapping[]) claimMappingObject;
                if (mockRealm) {
                    identityTenantUtil.when(() -> IdentityTenantUtil.getRealm(anyString(), isNull()))
                            .thenReturn(mockedUserRealm);
                } else {
                    identityTenantUtil.when(() -> IdentityTenantUtil.getRealm(anyString(), anyString()))
                            .thenReturn(null);
                }

                lenient().when(mockedOAuthServerConfiguration.isMapFederatedUsersToLocal())
                        .thenReturn(mapFedUsersToLocal);

                mockOAuth2Util(oAuth2Util);

                AuthenticatedUser authenticatedUser = getAuthenticatedUser("carbon.super", userStoreDomain,
                        "test-user", isFederated, "4b4414e1-916b-4475-aaee-6b0751c29f11");

                frameworkUtils.when(() -> FrameworkUtils.resolveUserIdFromUsername(anyInt(), anyString(), anyString()))
                        .thenReturn("4b4414e1-916b-4475-aaee-6b0751c29f11");

                AccessTokenDO accessTokenDO = getAccessTokenDO(clientId, authenticatedUser);
                if (mockAccessTokenDO) {
                    oAuth2Util.when(() -> OAuth2Util.getAccessTokenIdentifier(any())).thenReturn("DummyIdentifier");
                    oAuth2Util.when(() -> OAuth2Util.getAccessTokenDOfromTokenIdentifier(anyString()))
                            .thenReturn(accessTokenDO);
                    oAuth2Util.when(() -> OAuth2Util.findAccessToken(any(), anyBoolean())).thenReturn(accessTokenDO);
                }

                oAuth2ServiceComponentHolder.when(OAuth2ServiceComponentHolder::getApplicationMgtService).thenReturn(
                        mockedApplicationManagementService);
                lenient().when(mockedApplicationManagementService.getServiceProviderNameByClientId(
                        anyString(), anyString(), anyString())).thenReturn("SP1");

                if (mockServiceProvider) {
                    lenient().when(
                            mockedApplicationManagementService.getServiceProviderByClientId(anyString(), anyString(),
                                    anyString())).thenReturn(mockedServiceProvider);
                }

                lenient().when(mockedValidationTokenResponseDTO.getAuthorizedUser()).thenReturn(AUTHORIZED_USER);
                when(mockedValidationTokenResponseDTO.getAuthorizationContextToken()).thenReturn(
                        mockedAuthzContextToken);
                mockedUserStoreManager = mock(AbstractUserStoreManager.class);
                when(mockedUserRealm.getUserStoreManager()).thenReturn(mockedUserStoreManager);

                lenient().when(mockedServiceProvider.getClaimConfig()).thenReturn(mockedClaimConfig);
                lenient().when(mockedClaimConfig.getClaimMappings()).thenReturn(claimMappings);

                lenient().when(mockedServiceProvider.getLocalAndOutBoundAuthenticationConfig()).thenReturn(
                        mockedLocalAndOutboundConfig);
                lenient().when(mockedLocalAndOutboundConfig.getSubjectClaimUri()).thenReturn(subjectClaimUri);

                claimMetadataHandler.when(ClaimMetadataHandler::getInstance).thenReturn(mockedClaimMetadataHandler);
                lenient().when(mockedClaimMetadataHandler.getMappingsMapFromOtherDialectToCarbon(
                        anyString(), isNull(), anyString(), anyBoolean())).thenReturn(spToLocalClaimMappings);

                if (userClaimsMap != null) {
                    lenient().when(mockedUserStoreManager.getUserClaimValuesWithID(anyString(), any(String[].class),
                                    isNull())).
                            thenReturn(userClaimsMap);
                    ServiceProviderProperty serviceProviderProperty = new ServiceProviderProperty();
                    serviceProviderProperty.setName(IS_FRAGMENT_APP);
                    serviceProviderProperty.setValue(Boolean.TRUE.toString());
                    ServiceProviderProperty[] serviceProviderProperties = new ServiceProviderProperty[1];
                    serviceProviderProperties[0] = serviceProviderProperty;
                    lenient().when(mockedServiceProvider.getSpProperties()).thenReturn(serviceProviderProperties);

                    AssociatedRolesConfig associatedRolesConfig = new AssociatedRolesConfig();
                    associatedRolesConfig.setAllowedAudience(RoleConstants.ORGANIZATION);
                    lenient().when(mockedServiceProvider.getAssociatedRolesConfig()).thenReturn(associatedRolesConfig);
                } else {
                    when(mockedUserStoreManager.getUserClaimValuesWithID(anyString(), any(String[].class), isNull())).
                            thenThrow(new UserStoreException("UserNotFound"));
                }

                identityUtil.when(() -> IdentityUtil.extractDomainFromName(anyString())).thenReturn(userStoreDomain);

                lenient().when(mockedUserRealm.getUserStoreManager()).thenReturn(mockedUserStoreManager);
                lenient().when(mockedUserStoreManager.getSecondaryUserStoreManager(anyString())).thenReturn(
                        mockedUserStoreManager);
                lenient().when(mockedUserStoreManager.getRealmConfiguration()).thenReturn(mockedRealmConfiguration);
                lenient().when(mockedRealmConfiguration.getUserStoreProperty(
                        IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR)).thenReturn(claimSeparator);

                lenient().when(mockedServiceProvider.getPermissionAndRoleConfig())
                        .thenReturn(mockedPermissionAndRoleConfig);
                lenient().when(mockedPermissionAndRoleConfig.getRoleMappings()).thenReturn(roleMappings);

                OAuth2ServiceComponentHolder oAuth2ServiceComponentHolderInstance =
                        mock(OAuth2ServiceComponentHolder.class);
                when(OAuth2ServiceComponentHolder.getInstance()).thenReturn(oAuth2ServiceComponentHolderInstance);
                when(oAuth2ServiceComponentHolderInstance.getTokenProvider())
                        .thenReturn(new DefaultTokenProvider());
                lenient().when(oAuth2ServiceComponentHolderInstance.getRoleManagementServiceV2())
                        .thenReturn(mockedRoleManagementService);

                Set<String> roleGroupClaimURIs = new HashSet<>();
                roleGroupClaimURIs.add("http://wso2.org/claims/role");
                roleGroupClaimURIs.add("http://wso2.org/claims/roles");
                roleGroupClaimURIs.add("http://wso2.org/claims/groups");

                identityUtil.when(IdentityUtil::getRoleGroupClaims).thenReturn(roleGroupClaimURIs);

                Map<String, Object> claimsMap;
                try {
                    claimsMap = ClaimUtil.getClaimsFromUserStore(mockedValidationTokenResponseDTO);
                    Assert.assertEquals(claimsMap.size(), expectedMapSize);
                } catch (UserInfoEndpointException e) {
                    Assert.assertEquals(expectedMapSize, -1, "Unexpected exception thrown");
                }
            }
        }
    }

    protected void mockOAuth2Util(MockedStatic<OAuth2Util> oAuth2Util)
            throws IdentityOAuth2Exception, InvalidOAuthClientException {

        oAuth2Util.when(() -> OAuth2Util.getAuthenticatedUser(any(AccessTokenDO.class))).thenCallRealMethod();
        oAuth2Util.when(() -> OAuth2Util.isFederatedUser(any(AuthenticatedUser.class))).thenCallRealMethod();
        oAuth2Util.when(() -> OAuth2Util.getAppInformationByClientId(anyString())).thenReturn(mockedOAuthAppDO);
        oAuth2Util.when(() -> OAuth2Util.getTenantDomainOfOauthApp(any(OAuthAppDO.class))).thenReturn("carbon.super");
        oAuth2Util.when(() -> OAuth2Util.getServiceProvider(anyString(), anyString())).thenCallRealMethod();
    }

    private AccessTokenDO getAccessTokenDO(String clientId, AuthenticatedUser authenticatedUser) {
    
        AccessTokenDO accessTokenDO = new AccessTokenDO();
        accessTokenDO.setConsumerKey(clientId);
        accessTokenDO.setAuthzUser(authenticatedUser);
        return accessTokenDO;
    }

    private AuthenticatedUser getAuthenticatedUser(String tenantDomain, String userStoreDomain, String username,
                                                   boolean isFederated, String userId) {

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setTenantDomain(tenantDomain);
        authenticatedUser.setUserStoreDomain(userStoreDomain);
        authenticatedUser.setUserName(username);
        authenticatedUser.setUserId(userId);
        authenticatedUser.setFederatedUser(isFederated);
        return authenticatedUser;
    }

    @DataProvider(name = "provideRoleMappingData")
    public Object[][] provideRoleMappingData() {

        return new Object[][]{
                {new ArrayList<String>(), roleMappings, ",", null},
                {null, null, ",", null},
                {new ArrayList<String>() {{
                    add("role1");
                    add("role2");
                }}, null, ",,,", "role1,,,role2"},
                {new ArrayList<String>() {{
                    add("role1");
                    add("role2");
                }}, roleMappings, "#", "remoteRole1#remoteRole2"},
                {new ArrayList<String>() {{
                    add("role1");
                }}, new RoleMapping[0], ",", "role1"}
        };
    }

    @Test(dataProvider = "provideRoleMappingData")
    public void testGetServiceProviderMappedUserRoles(List<String> locallyMappedUserRoles,
                                                      Object roleMappingObject,
                                                      String claimSeparator,
                                                      String expected) throws Exception {

        RoleMapping[] roleMappings = (RoleMapping[]) roleMappingObject;
        lenient().when(mockedServiceProvider.getPermissionAndRoleConfig()).thenReturn(mockedPermissionAndRoleConfig);
        lenient().when(mockedPermissionAndRoleConfig.getRoleMappings()).thenReturn(roleMappings);
        String returned = ClaimUtil.getServiceProviderMappedUserRoles(mockedServiceProvider,
                locallyMappedUserRoles, claimSeparator);
        Assert.assertEquals(returned, expected, "Invalid returned value");
    }
}
