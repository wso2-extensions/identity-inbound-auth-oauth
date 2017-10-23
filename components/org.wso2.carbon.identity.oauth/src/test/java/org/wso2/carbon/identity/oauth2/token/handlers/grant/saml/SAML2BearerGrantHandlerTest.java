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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.token.handlers.grant.saml;

import com.google.gdata.util.common.base.Charsets;
import org.apache.commons.codec.binary.Base64;
import org.joda.time.DateTime;
import org.mockito.Mock;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.validation.ValidationException;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.Claim;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.LocalAndOutboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.TestConstants;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuer;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.sso.saml.SSOServiceProviderConfigManager;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOAuthnReqDTO;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.lang.reflect.Field;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;
import static org.powermock.api.mockito.PowerMockito.doNothing;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.assertEquals;

/**
 * tests for SAML2BearerGrantHandler
 */
@PowerMockIgnore({"javax.net.*"})
@PrepareForTest({IdentityUtil.class, IdentityTenantUtil.class, IdentityProviderManager.class, MultitenantUtils.class,
        IdentityApplicationManagementUtil.class, OAuthServerConfiguration.class, SSOServiceProviderConfigManager.class,
        SAML2BearerGrantHandler.class, OAuthComponentServiceHolder.class, OAuth2ServiceComponentHolder.class,
        OAuth2Util.class,})
public class SAML2BearerGrantHandlerTest extends PowerMockIdentityBaseTest {

    private SAML2BearerGrantHandler saml2BearerGrantHandler;
    private Assertion assertion;
    private ServiceProvider serviceProvider;
    private FederatedAuthenticatorConfig samlConfig;
    private FederatedAuthenticatorConfig oauthConfig;
    private FederatedAuthenticatorConfig federatedAuthenticatorConfig;

    @Mock
    private OauthTokenIssuer oauthIssuer;
    @Mock
    private OAuthComponentServiceHolder oAuthComponentServiceHolder;
    @Mock
    private RealmService realmService;
    @Mock
    private TenantManager tenantManager;
    @Mock
    private IdentityProviderManager identityProviderManager;
    @Mock
    private SSOServiceProviderConfigManager ssoServiceProviderConfigManager;
    @Mock
    private OAuthTokenReqMessageContext tokReqMsgCtx;
    @Mock
    private OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO;
    @Mock
    private OAuthServerConfiguration oAuthServerConfiguration;
    @Mock
    private SAMLSignatureProfileValidator profileValidator;
    @Mock
    private X509Certificate x509Certificate;
    @Mock
    private SignatureValidator signatureValidator;
    @Mock
    private UserStoreManager userStoreManager;
    @Mock
    private UserRealm userRealm;
    @Mock
    private ApplicationManagementService applicationManagementService;
    @Mock
    private TokenPersistenceProcessor persistenceProcessor;

    @BeforeMethod
    public void setUp() throws Exception {

        mockStatic(OAuthServerConfiguration.class);
        mockStatic(IdentityUtil.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);
        when(oAuthServerConfiguration.getIdentityOauthTokenIssuer()).thenReturn(oauthIssuer);
        when(oAuthServerConfiguration.getPersistenceProcessor()).thenReturn(persistenceProcessor);
        federatedAuthenticatorConfig = new FederatedAuthenticatorConfig();
        saml2BearerGrantHandler = new SAML2BearerGrantHandler();
        saml2BearerGrantHandler.init();
        oAuth2AccessTokenReqDTO = new OAuth2AccessTokenReqDTO();
        tokReqMsgCtx = new OAuthTokenReqMessageContext(oAuth2AccessTokenReqDTO);
        tokReqMsgCtx.setTenantID(-1234);
        assertion = buildAssertion();
    }

    @Test
    public void testValidateGrant() throws Exception {

        initSAMLGrant();
        assertTrue(saml2BearerGrantHandler.validateGrant(tokReqMsgCtx));
    }

    @Test
    public void testValidateGrantWhenSAMLPropertyNull() throws Exception {

        initSAMLGrant();
        when(IdentityApplicationManagementUtil.getProperty(samlConfig.getProperties(), "IdPEntityId"))
                .thenReturn(getProperty("samlsso", null));
        assertFalse(saml2BearerGrantHandler.validateGrant(tokReqMsgCtx));
    }

    @Test
    public void testValidateGrantWhenSAMLPropertyInvalid() throws Exception {

        initSAMLGrant();
        when(IdentityApplicationManagementUtil.getProperty(samlConfig.getProperties(), "IdPEntityId"))
                .thenReturn(getProperty("samlsso", "notLocalHost"));
        assertFalse(saml2BearerGrantHandler.validateGrant(tokReqMsgCtx));
    }

    @Test
    public void testValidateGrantWhenFACIsInvalid() throws Exception {

        initSAMLGrant();
        federatedAuthenticatorConfig.setProperties(new Property[]{getProperty(IdentityApplicationConstants
                .Authenticator.SAML2SSO.IDP_ENTITY_ID, "notLocal")});
        assertTrue(saml2BearerGrantHandler.validateGrant(tokReqMsgCtx));
    }

    @Test
    public void testValidateGrantWhenIDPIsNull() throws Exception {

        initSAMLGrant();
        when(identityProviderManager
                .getIdPByAuthenticatorPropertyValue(anyString(), anyString(), anyString(), anyString(), anyBoolean()))
                .thenReturn(null);
        assertFalse(saml2BearerGrantHandler.validateGrant(tokReqMsgCtx));
    }

    @DataProvider(name = "validateGrantWhenAuthDiffer")
    public Object[][] authenticator() {

        return new Object[][]{
                {"samlsso"},
                {"SAMLSSOAuthenticator"}
        };
    }

    @Test(dataProvider = "validateGrantWhenAuthDiffer")
    public void testValidateGrantWhenAuthDiffer(String authenticator) throws Exception {

        initSAMLGrant();
        when(identityProviderManager
                .getIdPByAuthenticatorPropertyValue("IdPEntityId", "localhost", "carbon.super", authenticator, false))
                .thenReturn(null);
        assertTrue(saml2BearerGrantHandler.validateGrant(tokReqMsgCtx));
    }

    @Test
    public void testValidateGrantWhenOauthConfigIsInvalid() throws Exception {

        initSAMLGrant();
        when(IdentityApplicationManagementUtil.getProperty(oauthConfig.getProperties(), "OAuth2TokenEPUrl"))
                .thenReturn(getProperty("TokenEPUrl", "notLocal"));
        assertFalse(saml2BearerGrantHandler.validateGrant(tokReqMsgCtx));
    }

    @DataProvider(name = "ValidateGrantForDifferentProperty")
    public Object[][] property() {

        return new Object[][]{
                {"IdPEntityId"},
                {"OAuth2TokenEPUrl"}
        };
    }

    @Test(dataProvider = "ValidateGrantForDifferentProperty")
    public void testValidateGrantForDifferentProperty(String propertyName) throws Exception {

        initSAMLGrant();
        when(IdentityApplicationManagementUtil.getProperty(samlConfig.getProperties(), propertyName))
                .thenReturn(null);
        assertFalse(saml2BearerGrantHandler.validateGrant(tokReqMsgCtx));
    }

    @Test
    public void testValidateGrantWhenInvalidNotOnOrAfter() throws Exception {

        initSAMLGrant();
        when(oAuthServerConfiguration.getTimeStampSkewInSeconds()).thenReturn(-1000000000000000L);
        assertFalse(saml2BearerGrantHandler.validateGrant(tokReqMsgCtx));
    }

    @Test
    public void testValidateGrantForEmptyIDPAlias() throws Exception {

        initSAMLGrant();
        IdentityProvider identityProvider = getIdentityProvider("notLocal");
        identityProvider.setAlias("");
        when(IdentityProviderManager.getInstance()).thenReturn(identityProviderManager);
        when(identityProviderManager
                .getIdPByAuthenticatorPropertyValue(anyString(), anyString(), anyString(), anyString(), anyBoolean()))
                .thenReturn(identityProvider);
        assertFalse(saml2BearerGrantHandler.validateGrant(tokReqMsgCtx));
    }

    @Test
    public void testValidateGrantForValidationException() throws Exception {

        initSAMLGrant();
        whenNew(SignatureValidator.class).withArguments(any(X509Credential.class)).thenThrow(ValidationException.class);
        assertFalse(saml2BearerGrantHandler.validateGrant(tokReqMsgCtx),"Error while validating the signature.");
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testValidateGrantIPMException() throws Exception {

        initAssertion();
        initIdentityProviderManager();
        when(identityProviderManager
                .getIdPByAuthenticatorPropertyValue(anyString(), anyString(), anyString(), anyString(), anyBoolean()))
                .thenThrow(IdentityProviderManagementException.class);
        assertFalse(saml2BearerGrantHandler.validateGrant(tokReqMsgCtx),
                "Error while getting an Identity Provider for issuer value :" + assertion.getIssuer().getValue());
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testValidateGrantForCertificateException() throws Exception {

        initSAMLGrant();
        when(IdentityApplicationManagementUtil.decodeCertificate(anyString()))
                .thenThrow(CertificateException.class);
        assertTrue(saml2BearerGrantHandler.validateGrant(tokReqMsgCtx),"Error occurred while decoding public certificate of Identity Provider");
    }

    @Test
    public void testIssueRefreshToken() throws Exception {

        when(oAuthServerConfiguration.getValueForIsRefreshTokenAllowed(OAuthConstants.OAUTH_SAML2_BEARER_METHOD)).thenReturn(true);
        assertTrue(saml2BearerGrantHandler.issueRefreshToken());
    }

    @Test
    public void testSetUserForFederatedUserType() throws Exception {

        IdentityProvider identityProvider = getIdentityProvider(null);
        when(oAuthServerConfiguration.getSaml2BearerTokenUserType()).thenReturn(OAuthConstants.UserType.FEDERATED_USER_DOMAIN_PREFIX);
        saml2BearerGrantHandler.setUser(tokReqMsgCtx, identityProvider, assertion, TestConstants.CARBON_TENANT_DOMAIN);
        assertEquals(tokReqMsgCtx.getAuthorizedUser().getUserName(), assertion.getSubject().getNameID().getValue());
    }

    @Test
    public void testSetUserForLocalUserType() throws Exception {

        IdentityProvider identityProvider = getIdentityProvider(null);
        when(oAuthServerConfiguration.getSaml2BearerTokenUserType()).thenReturn(OAuthConstants.UserType.LOCAL_USER_TYPE);
        mockOAuthComponents();
        when(realmService.getTenantUserRealm(anyInt())).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userStoreManager.isExistingUser(anyString())).thenReturn(true);
        saml2BearerGrantHandler.setUser(tokReqMsgCtx, identityProvider, assertion, TestConstants.CARBON_TENANT_DOMAIN);
        assertEquals(tokReqMsgCtx.getAuthorizedUser().getUserName(), assertion.getSubject().getNameID().getValue(),
                "the local user set to the token req message context after validating the user");
    }

    @Test
    public void testSetUserForLocalIDP() throws Exception {

        IdentityProvider identityProvider = new IdentityProvider();
        when(oAuthServerConfiguration.getSaml2BearerTokenUserType()).thenReturn("notValid");
        mockOAuthComponents();
        when(realmService.getTenantUserRealm(anyInt())).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userStoreManager.isExistingUser(anyString())).thenReturn(true);
        identityProvider.setIdentityProviderName(IdentityApplicationConstants.RESIDENT_IDP_RESERVED_NAME);
        saml2BearerGrantHandler.setUser(tokReqMsgCtx, identityProvider, assertion, TestConstants.CARBON_TENANT_DOMAIN);
        assertEquals(tokReqMsgCtx.getAuthorizedUser().getUserName(), assertion.getSubject().getNameID().getValue(),
                "Set the local user identified from subject identifier from assertion");
    }

    @Test
    public void testSetUserForNonLocalIDP() throws Exception {

        IdentityProvider identityProvider = getIdentityProvider("notLocal");
        when(oAuthServerConfiguration.getSaml2BearerTokenUserType()).thenReturn("notValid");
        mockOAuthComponents();
        when(realmService.getTenantUserRealm(anyInt())).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userStoreManager.isExistingUser(anyString())).thenReturn(true);
        saml2BearerGrantHandler.setUser(tokReqMsgCtx, identityProvider, assertion, TestConstants.CARBON_TENANT_DOMAIN);
        assertEquals(tokReqMsgCtx.getAuthorizedUser().getUserName(), assertion.getSubject().getNameID().getValue(),
                "Build and set Federated User when idp is not local");
    }

    @Test
    public void testSetUserForLegacyUser() throws Exception {

        mockStatic(OAuth2Util.class);
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        IdentityProvider identityProvider = getIdentityProvider(null);
        authenticatedUser.setAuthenticatedSubjectIdentifier(assertion.getSubject().getNameID().getValue());
        when(OAuth2Util.getUserFromUserName(anyString())).thenReturn(authenticatedUser);
        when(oAuthServerConfiguration.getSaml2BearerTokenUserType()).thenReturn(OAuthConstants.UserType.LEGACY_USER_TYPE);
        saml2BearerGrantHandler.setUser(tokReqMsgCtx, identityProvider, assertion, TestConstants.CARBON_TENANT_DOMAIN);
        String subject = tokReqMsgCtx.getAuthorizedUser().getAuthenticatedSubjectIdentifier();
        assertEquals(subject, authenticatedUser.getAuthenticatedSubjectIdentifier(),
                "setting the username to Token MessageContext from assertion by removing the domain name");
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testSetLocalUserForIAMException() throws Exception {

        mockOAuthComponents();
        when(OAuth2ServiceComponentHolder.getApplicationMgtService())
                .thenThrow(IdentityApplicationManagementException.class);
        saml2BearerGrantHandler.setLocalUser(tokReqMsgCtx, assertion, "notValid");
        assertEquals(tokReqMsgCtx.getAuthorizedUser().getUserName(), assertion.getSubject().getNameID().getValue(),
                "Error while retrieving service provider for invalid spTenantDomain.");
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testSetLocalUserForInvalidSP() throws Exception {

        mockOAuthComponents();
        when(realmService.getTenantUserRealm(anyInt())).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userStoreManager.isExistingUser(anyString())).thenReturn(true);
        serviceProvider.setSaasApp(false);
        saml2BearerGrantHandler.setLocalUser(tokReqMsgCtx, assertion, "notValid");
        assertEquals(tokReqMsgCtx.getAuthorizedUser().getUserName(), assertion.getSubject().getNameID().getValue(),
                "Non SaaS app tries to issue token for a different tenant domain.");
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testSetLocalUserForNotExistingUser() throws Exception {

        mockOAuthComponents();
        when(realmService.getTenantUserRealm(anyInt())).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userStoreManager.isExistingUser(anyString())).thenReturn(false);
        saml2BearerGrantHandler.setLocalUser(tokReqMsgCtx, assertion, TestConstants.CARBON_TENANT_DOMAIN);
        assertEquals(tokReqMsgCtx.getAuthorizedUser().getUserName(), assertion.getSubject().getNameID().getValue(),
                "User doesn't exist in local user store");
    }

    @DataProvider(name = "SetUserForInvalidUserStoreManager")
    public Object[][] userType() {

        return new Object[][]{
                {OAuthConstants.UserType.LOCAL_USER_TYPE},
                {"notValid"}
        };
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class, dataProvider = "SetUserForInvalidUserStoreManager")
    public void testSetUserForInvalidUserStoreManager(String userType) throws Exception {

        when(oAuthServerConfiguration.getSaml2BearerTokenUserType()).thenReturn(userType);
        serviceProvider = getServicProvider(false, false);

        mockStatic(OAuthComponentServiceHolder.class);
        when(OAuthComponentServiceHolder.getInstance()).thenReturn(oAuthComponentServiceHolder);
        when(oAuthComponentServiceHolder.getRealmService()).thenReturn(realmService);

        mockStatic(OAuth2ServiceComponentHolder.class);
        when(OAuth2ServiceComponentHolder.getApplicationMgtService()).thenReturn(applicationManagementService);
        when(applicationManagementService.getServiceProviderByClientId(anyString(), anyString(), anyString()))
                .thenReturn(serviceProvider);

        when(realmService.getTenantUserRealm(anyInt())).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenThrow(UserStoreException.class);
        IdentityProvider identityProvider = getIdentityProvider(IdentityApplicationConstants.RESIDENT_IDP_RESERVED_NAME);
        saml2BearerGrantHandler.setUser(tokReqMsgCtx, identityProvider, assertion, TestConstants.CARBON_TENANT_DOMAIN);
        assertEquals(tokReqMsgCtx.getAuthorizedUser().getUserName(), assertion.getSubject().getNameID().getValue(),
                "Error while building local user from given assertion");
    }

    @Test
    public void testBuildLocalUser() throws Exception {

        serviceProvider = getServicProvider(false, true);
        AuthenticatedUser authenticatedUser = saml2BearerGrantHandler.buildLocalUser(tokReqMsgCtx, assertion,
                serviceProvider, TestConstants.CARBON_TENANT_DOMAIN);
        assertEquals(authenticatedUser.getUserName(), TestConstants.TEST_USER_NAME);
    }

    @Test
    public void testBuildLocalUserWhenTenantDomainIsEmpty() throws Exception {

        serviceProvider = getServicProvider(false, true);
        mockStatic(MultitenantUtils.class);
        when(MultitenantUtils.getTenantDomain(anyString())).thenReturn("");
        AuthenticatedUser authenticatedUser = saml2BearerGrantHandler.buildLocalUser(tokReqMsgCtx, assertion,
                serviceProvider, TestConstants.CARBON_TENANT_DOMAIN);
        assertEquals(authenticatedUser.getTenantDomain(), TestConstants.CARBON_TENANT_DOMAIN,
                "userTenantDomain is set as spTenantDomain");
    }

    @Test
    public void testCreateLegacyUser() throws Exception {

        mockStatic(OAuth2Util.class);
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier(assertion.getSubject().getNameID().getValue());
        when(OAuth2Util.getUserFromUserName(anyString())).thenReturn(authenticatedUser);
        saml2BearerGrantHandler.createLegacyUser(tokReqMsgCtx, assertion);
        String subject = tokReqMsgCtx.getAuthorizedUser().getAuthenticatedSubjectIdentifier();
        assertEquals(subject, authenticatedUser.getAuthenticatedSubjectIdentifier(),
                "setting the username to Token MessageContext from assertion by removing the domain name");
    }

    private Property getProperty(String name, String value) {

        Property property = new Property();
        property.setName(name);
        property.setValue(value);
        return property;
    }

    private ServiceProvider getServicProvider(boolean isTenantDomainInSubject, boolean isUserstoreDomainInSubject) {

        serviceProvider = new ServiceProvider();
        serviceProvider.setSaasApp(true);
        LocalAndOutboundAuthenticationConfig localAndOutboundAuthenticationConfig
                = new LocalAndOutboundAuthenticationConfig();
        localAndOutboundAuthenticationConfig.setUseTenantDomainInLocalSubjectIdentifier(isTenantDomainInSubject);
        localAndOutboundAuthenticationConfig.setUseUserstoreDomainInLocalSubjectIdentifier(isUserstoreDomainInSubject);
        serviceProvider.setLocalAndOutBoundAuthenticationConfig(localAndOutboundAuthenticationConfig);
        return serviceProvider;
    }

    private void prepareForGetIssuer() throws Exception {

        when(tenantManager.getTenantId(anyString())).thenReturn(-1234);
        when(realmService.getTenantManager()).thenReturn(tenantManager);
        SAMLSSOUtil.setRealmService(realmService);

        federatedAuthenticatorConfig.setProperties(new Property[]
                {getProperty(IdentityApplicationConstants.Authenticator.SAML2SSO.IDP_ENTITY_ID,
                        TestConstants.LOACALHOST_DOMAIN)});
        federatedAuthenticatorConfig.setName( IdentityApplicationConstants.Authenticator.SAML2SSO.NAME);
        FederatedAuthenticatorConfig[] fedAuthConfs = {federatedAuthenticatorConfig};
        IdentityProvider identityProvider =getIdentityProvider(null);
        identityProvider.setFederatedAuthenticatorConfigs(fedAuthConfs);
        mockStatic(IdentityProviderManager.class);
        when(IdentityProviderManager.getInstance()).thenReturn(identityProviderManager);
        when(identityProviderManager.getResidentIdP(anyString())).thenReturn(identityProvider);
    }

    private void prepareForUserAttributes(String attrConsumerIndex, String issuer, String spName) {

        mockStatic(SSOServiceProviderConfigManager.class);
        when(SSOServiceProviderConfigManager.getInstance()).thenReturn(ssoServiceProviderConfigManager);
        SAMLSSOServiceProviderDO samlssoServiceProviderDO = new SAMLSSOServiceProviderDO();
        samlssoServiceProviderDO.setAttributeConsumingServiceIndex(attrConsumerIndex);
        samlssoServiceProviderDO.setEnableAttributesByDefault(true);
        samlssoServiceProviderDO.setIssuer(issuer);
        ssoServiceProviderConfigManager.addServiceProvider(issuer, samlssoServiceProviderDO);
        when(ssoServiceProviderConfigManager.getServiceProvider(spName)).thenReturn(samlssoServiceProviderDO);
    }

    private Assertion buildAssertion() throws Exception {

        prepareForGetIssuer();
        mockStatic(IdentityTenantUtil.class);
        when(IdentityUtil.getServerURL(anyString(), anyBoolean(), anyBoolean()))
                .thenReturn(TestConstants.SAMPLE_SERVER_URL);
        prepareForUserAttributes(TestConstants.ATTRIBUTE_CONSUMER_INDEX, TestConstants.LOACALHOST_DOMAIN,
                TestConstants.LOACALHOST_DOMAIN);
        Map<String, String> inputAttributes = new HashMap<>();
        inputAttributes.put(TestConstants.CLAIM_URI1, TestConstants.CLAIM_VALUE1);
        inputAttributes.put(TestConstants.CLAIM_URI2, TestConstants.CLAIM_VALUE2);
        SAMLSSOAuthnReqDTO authnReqDTO = buildAuthnReqDTO(inputAttributes, TestConstants.SAMPLE_NAME_ID_FORMAT,
                TestConstants.LOACALHOST_DOMAIN, TestConstants.TEST_USER_NAME);
        authnReqDTO.setNameIDFormat(TestConstants.SAMPLE_NAME_ID_FORMAT);
        authnReqDTO.setIssuer(TestConstants.LOACALHOST_DOMAIN);
        assertion = SAMLSSOUtil.buildSAMLAssertion(authnReqDTO, new DateTime(System.currentTimeMillis() + 10000000L),
                TestConstants.SESSION_ID);
        return assertion;
    }

    private ClaimMapping buildClaimMapping(String claimUri) {

        ClaimMapping claimMapping = new ClaimMapping();
        Claim claim = new Claim();
        claim.setClaimUri(claimUri);
        claimMapping.setRemoteClaim(claim);
        claimMapping.setLocalClaim(claim);
        return claimMapping;
    }

    private SAMLSSOAuthnReqDTO buildAuthnReqDTO(Map<String, String> attributes, String nameIDFormat, String issuer,
                                                String subjectName) {

        SAMLSSOAuthnReqDTO authnReqDTO = new SAMLSSOAuthnReqDTO();
        authnReqDTO.setUser(AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(subjectName));
        authnReqDTO.setNameIDFormat(nameIDFormat);
        authnReqDTO.setIssuer(issuer);
        Map<ClaimMapping, String> userAttributes = new HashMap<>();

        for (Map.Entry<String, String> entry : attributes.entrySet()) {
            userAttributes.put(buildClaimMapping(entry.getKey()), entry.getValue());
        }
        authnReqDTO.getUser().setUserAttributes(userAttributes);
        return authnReqDTO;
    }

    private void mockOAuthComponents() throws Exception {

        serviceProvider = getServicProvider(false, false);
        mockStatic(OAuthComponentServiceHolder.class);
        when(OAuthComponentServiceHolder.getInstance()).thenReturn(oAuthComponentServiceHolder);
        when(oAuthComponentServiceHolder.getRealmService()).thenReturn(realmService);
        mockStatic(OAuth2ServiceComponentHolder.class);
        when(OAuth2ServiceComponentHolder.getApplicationMgtService()).thenReturn(applicationManagementService);
        when(applicationManagementService.getServiceProviderByClientId(anyString(), anyString(), anyString()))
                .thenReturn(serviceProvider);
    }

    private IdentityProvider getIdentityProvider(String name){

        IdentityProvider identityProvider = new IdentityProvider();
        identityProvider.setIdentityProviderName(name);
        return identityProvider;
    }

    private void initIdentityProviderManager() throws Exception {

        mockStatic(IdentityApplicationManagementUtil.class);
        IdentityProvider identityProviderIns = getIdentityProvider("LOCAL");
        when(IdentityProviderManager.getInstance()).thenReturn(identityProviderManager);
        when(identityProviderManager
                .getIdPByAuthenticatorPropertyValue(anyString(), anyString(), anyString(), anyString(), anyBoolean()))
                .thenReturn(identityProviderIns);
    }

    private void initFederatedAuthConfig() {

        oauthConfig = new FederatedAuthenticatorConfig();
        samlConfig = new FederatedAuthenticatorConfig();

        IdentityProvider identityProvider = getIdentityProvider(null);
        federatedAuthenticatorConfig.setProperties(new Property[]{getProperty(IdentityApplicationConstants
                .Authenticator.SAML2SSO.IDP_ENTITY_ID, TestConstants.LOACALHOST_DOMAIN)});
        federatedAuthenticatorConfig.setName(IdentityApplicationConstants.Authenticator.SAML2SSO.NAME);
        FederatedAuthenticatorConfig[] fedAuthConfs = {federatedAuthenticatorConfig};
        identityProvider.setFederatedAuthenticatorConfigs(fedAuthConfs);

        when(IdentityApplicationManagementUtil.getFederatedAuthenticator(fedAuthConfs, "samlsso"))
                .thenReturn(samlConfig);
        when(IdentityApplicationManagementUtil.getFederatedAuthenticator(fedAuthConfs, "openidconnect"))
                .thenReturn(oauthConfig);
        when(IdentityApplicationManagementUtil.getProperty(samlConfig.getProperties(), "IdPEntityId"))
                .thenReturn(getProperty("samlsso", TestConstants.LOACALHOST_DOMAIN));
        when(IdentityApplicationManagementUtil.getProperty(oauthConfig.getProperties(), "OAuth2TokenEPUrl"))
                .thenReturn(getProperty("OAuth2TokenEPUrl", TestConstants.LOACALHOST_DOMAIN));
    }

    private void initAssertion() throws Exception {

        String assertionString = SAMLSSOUtil.marshall(assertion);
        assertionString = new String(Base64.encodeBase64(assertionString.getBytes(Charsets.UTF_8)));
        oAuth2AccessTokenReqDTO.setAssertion(assertionString);
        when(IdentityUtil.unmarshall(anyString())).thenReturn(assertion);
        when(IdentityUtil.isTokenLoggable(anyString())).thenReturn(true);
    }

    private void initSignatureValidator() throws Exception {

        Field field = SAML2BearerGrantHandler.class.getDeclaredField("profileValidator");
        field.setAccessible(true);
        field.set(saml2BearerGrantHandler, profileValidator);
        field.setAccessible(false);
        doNothing().when(profileValidator).validate(any(Signature.class));

        Certificate certificate = x509Certificate;
        when(IdentityApplicationManagementUtil.decodeCertificate(anyString()))
                .thenReturn(certificate);
        whenNew(SignatureValidator.class).withArguments(any(X509Credential.class)).thenReturn(signatureValidator);
        doNothing().when(signatureValidator).validate(any(Signature.class));
    }

    private void initSAMLGrant() throws Exception {

        initAssertion();
        initIdentityProviderManager();
        initFederatedAuthConfig();
        initSignatureValidator();
        SAML2TokenCallbackHandler callbackHandler = new SAML2TokenCallbackHandler() {
            @Override
            public void handleSAML2Token(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {
                //doNothingForTestingPurpose
            }
        };
        when(oAuthServerConfiguration.getSAML2TokenCallbackHandler()).thenReturn(callbackHandler);
    }

}
