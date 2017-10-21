/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
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
import org.mockito.Spy;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.impl.AttributeBuilder;
import org.opensaml.xml.XMLObject;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.w3c.dom.Element;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.ClaimConfig;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataHandler;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.registry.api.RegistryException;
import org.wso2.carbon.registry.core.Resource;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.registry.core.session.UserRegistry;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anySet;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

/**
 * Class which tests SAMLAssertionClaimsCallback.
 */
@PowerMockIgnore("javax.xml.*")
@PrepareForTest({
        AuthorizationGrantCache.class,
        PrivilegedCarbonContext.class,
        IdentityTenantUtil.class,
        OAuth2ServiceComponentHolder.class,
        ClaimMetadataHandler.class,
        UserCoreUtil.class
})
public class SAMLAssertionClaimsCallbackTest {

    private static final String SAMPLE_ACCESS_TOKEN = "4952b467-86b2-31df-b63c-0bf25cec4f86";
    private static final int SAMPLE_TENANT_ID = 1234;
    private static final String SAMPLE_TENANT_DOMAIN = "dummy_domain";
    private static final String SAMPLE_CLIENT_ID = "u5FIfG5xzLvBGiamoAYzzcqpBqga";
    private static final String SAMPLE_SERVICE_PROVIDER = "sampleSP";
    private static final String carbonHome = Paths.get(System.getProperty("user.dir"), "target").toString();
    private JWTClaimsSet jwtClaimsSet;

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }

    @Spy
    private SAMLAssertionClaimsCallback samlAssertionClaimsCallback;

    @Spy
    private AuthorizationGrantCache authorizationGrantCache;

    @Mock
    private OAuthTokenReqMessageContext requestMsgCtx;

    @Mock
    private OAuthAuthzReqMessageContext oAuthAuthzReqMessageContext;

    @Spy
    private PrivilegedCarbonContext context;

    @Mock
    private UserRealm userRealm;

    @Mock
    private UserStoreManager userStoreManager;

    @Mock
    private RealmConfiguration realmConfiguration;

    @Mock
    private RealmService realmService;

    @Mock
    private Assertion assertion;

    @Mock
    private Subject mockSubject;

    @Mock
    private NameID nameID;

    @Mock
    private RegistryService registry;

    @Mock
    private Resource resource;

    @Mock
    private UserRegistry userRegistry;

    @Mock
    private ApplicationManagementService applicationManagementService;

    @BeforeTest
    public void setUp() throws Exception {
        System.setProperty(CarbonBaseConstants.CARBON_HOME, carbonHome);

        OAuthComponentServiceHolder oAuthComponentServiceHolder = OAuthComponentServiceHolder.getInstance();
        realmService = mock(RealmService.class);
        oAuthComponentServiceHolder.setRealmService(realmService);
        userRealm = mock(UserRealm.class);
        when(realmService.getTenantUserRealm(anyInt())).thenReturn(userRealm);

        userStoreManager = mock(UserStoreManager.class);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);

        realmConfiguration = mock(RealmConfiguration.class);
        when(userStoreManager.getRealmConfiguration()).thenReturn(realmConfiguration);

        when(realmConfiguration.getUserStoreProperty(IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR)).
                thenReturn(IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR_DEFAULT);

        samlAssertionClaimsCallback = new SAMLAssertionClaimsCallback();
    }

    @Test
    public void testHandleCustomClaims() throws Exception {
        jwtClaimsSet = new JWTClaimsSet();
        requestMsgCtx = mock(OAuthTokenReqMessageContext.class);
        Assertion assertion = mock(Assertion.class);
        when(requestMsgCtx.getProperty(OAuthConstants.OAUTH_SAML2_ASSERTION)).thenReturn(assertion);
        samlAssertionClaimsCallback.handleCustomClaims(jwtClaimsSet, requestMsgCtx);
        assertTrue(!jwtClaimsSet.getAllClaims().isEmpty(), "Claims are successfully set.");
    }

    @Test
    public void testCustomClaimForOAuthTokenReqMessageContext() throws Exception {
        jwtClaimsSet = new JWTClaimsSet();
        requestMsgCtx = mock(OAuthTokenReqMessageContext.class);
        Assertion assertion = mock(Assertion.class);

        AttributeStatement statement = mock(AttributeStatement.class);
        List<AttributeStatement> attributeStatementList = new ArrayList<>();
        attributeStatementList.add(statement);
        when(assertion.getAttributeStatements()).thenReturn(attributeStatementList);

        List<Attribute> attributesList = new ArrayList<>();
        Attribute attribute = new AttributeBuilder().buildObject("urn:oasis:names:tc:SAML:2.0:assertion",
                "Attribute", "saml2");
        XMLObject obj = mock(XMLObject.class);
        attribute.getAttributeValues().add(obj);

        Element ele = mock(Element.class);
        when(obj.getDOM()).thenReturn(ele);
        attributesList.add(attribute);

        when(statement.getAttributes()).thenReturn(attributesList);
        when(requestMsgCtx.getProperty(OAuthConstants.OAUTH_SAML2_ASSERTION)).thenReturn(assertion);
        samlAssertionClaimsCallback.handleCustomClaims(jwtClaimsSet, requestMsgCtx);
        assertEquals(jwtClaimsSet.getAllClaims().size(), 9, "Claims are not successfully set.");
    }

    @Test
    public void testHandleClaimsForOAuthAuthzReqMessageContext() throws Exception {
        jwtClaimsSet = new JWTClaimsSet();
        oAuthAuthzReqMessageContext = mock(OAuthAuthzReqMessageContext.class);
        String[] approvedScopes = {"openid", "testScope1", "testScope2"};
        when(oAuthAuthzReqMessageContext.getApprovedScope()).thenReturn(approvedScopes);
        when(oAuthAuthzReqMessageContext.getProperty(OAuthConstants.ACCESS_TOKEN))
                .thenReturn(SAMPLE_ACCESS_TOKEN);

        mockStatic(AuthorizationGrantCache.class);
        authorizationGrantCache = mock(AuthorizationGrantCache.class);
        AuthorizationGrantCacheEntry authorizationGrantCacheEntry = mock(AuthorizationGrantCacheEntry.class);
        when(AuthorizationGrantCache.getInstance()).thenReturn(authorizationGrantCache);
        when(authorizationGrantCache.getValueFromCache(any(AuthorizationGrantCacheKey.class))).
                thenReturn(authorizationGrantCacheEntry);

        OAuth2AuthorizeReqDTO oAuth2AuthorizeReqDTO = new OAuth2AuthorizeReqDTO();
        when(oAuthAuthzReqMessageContext.getAuthorizationReqDTO()).thenReturn(oAuth2AuthorizeReqDTO);

        AuthenticatedUser authenticatedUser = mock(AuthenticatedUser.class);
        oAuth2AuthorizeReqDTO.setUser(authenticatedUser);
        when(authenticatedUser.isFederatedUser()).thenReturn(true);

        mockStatic(PrivilegedCarbonContext.class);
        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId(anyString())).thenReturn(SAMPLE_TENANT_ID);

        context = mock(PrivilegedCarbonContext.class);
        when(PrivilegedCarbonContext.getThreadLocalCarbonContext()).thenReturn(context);

        registry = mock(RegistryService.class);
        mockStatic(OAuth2ServiceComponentHolder.class);
        when(OAuth2ServiceComponentHolder.getRegistryService()).thenReturn(registry);

        userRegistry = mock(UserRegistry.class);
        when(registry.getConfigSystemRegistry(SAMPLE_TENANT_ID)).thenReturn(userRegistry);

        resource = mock(Resource.class);
        when(userRegistry.get(OAuthConstants.SCOPE_RESOURCE_PATH)).thenReturn(resource);

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId(anyString())).thenReturn(SAMPLE_TENANT_ID);

        context = mock(PrivilegedCarbonContext.class);
        when(PrivilegedCarbonContext.getThreadLocalCarbonContext()).thenReturn(context);

        registry = mock(RegistryService.class);
        mockStatic(OAuth2ServiceComponentHolder.class);
        when(OAuth2ServiceComponentHolder.getRegistryService()).thenReturn(registry);

        userRegistry = mock(UserRegistry.class);
        when(registry.getConfigSystemRegistry(SAMPLE_TENANT_ID)).thenReturn(userRegistry);

        resource = mock(Resource.class);
        when(userRegistry.get(OAuthConstants.SCOPE_RESOURCE_PATH)).thenReturn(resource);

        samlAssertionClaimsCallback.handleCustomClaims(jwtClaimsSet, oAuthAuthzReqMessageContext);
        assertEquals(jwtClaimsSet.getAllClaims().size(), 8, "Claims are not successfully set.");
    }

    @Test
    public void testCustomClaimForOAuthTokenReqMessageContextWithNullAssertionSubject() throws Exception {
        jwtClaimsSet = new JWTClaimsSet();
        requestMsgCtx = mock(OAuthTokenReqMessageContext.class);

        mockSubject = mock(Subject.class);
        assertion = mock(Assertion.class);
        nameID = mock(NameID.class);
        when(assertion.getSubject()).thenReturn(mockSubject);
        when(mockSubject.getNameID()).thenReturn(nameID);
        when(nameID.getValue()).thenReturn(" C=US, O=NCSA-TEST, OU=User, CN=trscavo@uiuc.edu");

        AttributeStatement statement = mock(AttributeStatement.class);
        List<AttributeStatement> attributeStatementList = null;
        when(assertion.getAttributeStatements()).thenReturn(attributeStatementList);

        List<Attribute> attributesList = new ArrayList<>();
        Attribute attribute = new AttributeBuilder().buildObject("urn:oasis:names:tc:SAML:2.0:assertion",
                "Attribute", "saml2");
        XMLObject obj = mock(XMLObject.class);
        attribute.getAttributeValues().add(obj);

        Element ele = mock(Element.class);
        when(obj.getDOM()).thenReturn(ele);
        attributesList.add(attribute);
        when(statement.getAttributes()).thenReturn(attributesList);

        when(requestMsgCtx.getProperty(OAuthConstants.OAUTH_SAML2_ASSERTION)).thenReturn(assertion);
        samlAssertionClaimsCallback.handleCustomClaims(jwtClaimsSet, requestMsgCtx);

        assertEquals(jwtClaimsSet.getAllClaims().size(), 8, "Claims are not successfully set.");
    }

    @Test
    public void testCustomClaimForOAuthTokenReqMessageContextWithNullAssertion() throws Exception {
        jwtClaimsSet = new JWTClaimsSet();
        requestMsgCtx = mock(OAuthTokenReqMessageContext.class);
        String[] approvedScopes = {"openid", "testScope1", "testScope2"};

        when(requestMsgCtx.getScope()).thenReturn(approvedScopes);
        when(requestMsgCtx.getProperty(OAuthConstants.OAUTH_SAML2_ASSERTION)).thenReturn(null);
        when(requestMsgCtx.getProperty(OAuthConstants.ACCESS_TOKEN)).thenReturn(SAMPLE_ACCESS_TOKEN);

        mockStatic(AuthorizationGrantCache.class);
        authorizationGrantCache = mock(AuthorizationGrantCache.class);
        AuthorizationGrantCacheEntry authorizationGrantCacheEntry = mock(AuthorizationGrantCacheEntry.class);

        when(AuthorizationGrantCache.getInstance()).thenReturn(authorizationGrantCache);
        when(authorizationGrantCache.getValueFromCache(any(AuthorizationGrantCacheKey.class))).
                thenReturn(authorizationGrantCacheEntry);

        AuthenticatedUser user = mock(AuthenticatedUser.class);
        when(requestMsgCtx.getAuthorizedUser()).thenReturn(user);
        when(user.isFederatedUser()).thenReturn(false);

        OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO = mock(OAuth2AccessTokenReqDTO.class);
        when(requestMsgCtx.getOauth2AccessTokenReqDTO()).thenReturn(oAuth2AccessTokenReqDTO);
        when(oAuth2AccessTokenReqDTO.getTenantDomain()).thenReturn(SAMPLE_TENANT_DOMAIN);
        when(oAuth2AccessTokenReqDTO.getClientId()).thenReturn(SAMPLE_CLIENT_ID);

        mockStatic(OAuth2ServiceComponentHolder.class);
        applicationManagementService = mock(ApplicationManagementService.class);
        when(OAuth2ServiceComponentHolder.getApplicationMgtService()).thenReturn(applicationManagementService);
        when(applicationManagementService.getServiceProviderNameByClientId(anyString(), anyString(), anyString()))
                .thenReturn(SAMPLE_SERVICE_PROVIDER);

        getMockResourceFromScopes();

        samlAssertionClaimsCallback.handleCustomClaims(jwtClaimsSet, requestMsgCtx);
        assertEquals(jwtClaimsSet.getAllClaims().size(), 8, "Claims are not successfully set.");
    }

    @Test
    public void testHandleClaimsForOAuthAuthzReqMessageContextNullAccessToken() throws Exception {
        jwtClaimsSet = new JWTClaimsSet();
        oAuthAuthzReqMessageContext = mock(OAuthAuthzReqMessageContext.class);
        String[] approvedScopes = {"openid", "testScope1", "testScope2"};
        when(oAuthAuthzReqMessageContext.getApprovedScope()).thenReturn(approvedScopes);
        when(oAuthAuthzReqMessageContext.getProperty(OAuthConstants.ACCESS_TOKEN))
                .thenReturn(null);

        OAuth2AuthorizeReqDTO oAuth2AuthorizeReqDTO = new OAuth2AuthorizeReqDTO();
        when(oAuthAuthzReqMessageContext.getAuthorizationReqDTO()).thenReturn(oAuth2AuthorizeReqDTO);

        AuthenticatedUser authenticatedUser = mock(AuthenticatedUser.class);
        oAuth2AuthorizeReqDTO.setUser(authenticatedUser);
        when(authenticatedUser.isFederatedUser()).thenReturn(false);

        when(authenticatedUser.getUserName()).thenReturn("user1234");
        when(authenticatedUser.getUserStoreDomain()).thenReturn("abc.com");

        ApplicationManagementService mockApplicationManagementService = mock(ApplicationManagementService.class);
        mockStatic(OAuth2ServiceComponentHolder.class);
        when(OAuth2ServiceComponentHolder.getApplicationMgtService()).thenReturn(mockApplicationManagementService);

        when(mockApplicationManagementService.getServiceProviderNameByClientId(anyString(), anyString(), anyString()))
                .thenReturn(SAMPLE_SERVICE_PROVIDER);

        ServiceProvider serviceProvider = new ServiceProvider();
        ClaimConfig claimConfig = new ClaimConfig();
        ClaimMapping claimMap1 = ClaimMapping.build("http://www.wso2.org/claims/email", "http://www.abc.com/claims/email", "sample@abc.com", false);
        ClaimMapping claimMap2 = ClaimMapping.build("http://www.wso2.org/claims/username", "http://www.abc.com/claims/username", "user123", true);

        ClaimMapping[] requestedLocalClaimMap = {claimMap1, claimMap2};
        claimConfig.setClaimMappings(requestedLocalClaimMap);
        serviceProvider.setClaimConfig(claimConfig);

        when(mockApplicationManagementService.getApplicationExcludingFileBasedSPs(anyString(), anyString()))
                .thenReturn(serviceProvider);

        UserRealm sampleUserRealm = mock(UserRealm.class);
        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getRealm(anyString(), anyString())).thenReturn(sampleUserRealm);

        Map<String, String> spToLocalClaimMappings = new HashMap<>();
        mockStatic(ClaimMetadataHandler.class);
        ClaimMetadataHandler claimMetadataHandler = mock(ClaimMetadataHandler.class);

        when(ClaimMetadataHandler.getInstance()).thenReturn(claimMetadataHandler);
        when(claimMetadataHandler.getMappingsMapFromOtherDialectToCarbon(anyString(), anySet(), anyString(),
                anyBoolean())).thenReturn(spToLocalClaimMappings);

        Map<String, String> userClaims = new HashMap<>();
        mockStatic(UserCoreUtil.class);
        when(UserCoreUtil.addDomainToName(anyString(), anyString())).thenReturn("user1234@abc.com");

        userStoreManager = mock(UserStoreManager.class);
        when(sampleUserRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userStoreManager.getUserClaimValues(anyString(), any(String[].class), anyString())).thenReturn(userClaims);

        RealmConfiguration realmConfiguration = mock(RealmConfiguration.class);
        when(userStoreManager.getSecondaryUserStoreManager(anyString())).thenReturn(userStoreManager);
        when(userStoreManager.getRealmConfiguration()).thenReturn(realmConfiguration);
        when(realmConfiguration.getUserStoreProperty(IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR))
                .thenReturn(":");
        getMockResourceFromScopes();

        samlAssertionClaimsCallback.handleCustomClaims(jwtClaimsSet, oAuthAuthzReqMessageContext);
        assertEquals(jwtClaimsSet.getAllClaims().size(), 8, "Claims are not successfully set.");
    }

    private void getMockResourceFromScopes() throws RegistryException {
        System.setProperty(CarbonBaseConstants.CARBON_HOME, carbonHome);
        mockStatic(PrivilegedCarbonContext.class);
        context = mock(PrivilegedCarbonContext.class);
        when(PrivilegedCarbonContext.getThreadLocalCarbonContext()).thenReturn(context);

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId(anyString())).thenReturn(SAMPLE_TENANT_ID);

        RegistryService newRegistry = mock(RegistryService.class);
        when(OAuth2ServiceComponentHolder.getRegistryService()).thenReturn(newRegistry);

        when(newRegistry.getConfigSystemRegistry(anyInt())).thenReturn(userRegistry);
        when(userRegistry.get(OAuthConstants.SCOPE_RESOURCE_PATH)).thenReturn(resource);
    }
}
