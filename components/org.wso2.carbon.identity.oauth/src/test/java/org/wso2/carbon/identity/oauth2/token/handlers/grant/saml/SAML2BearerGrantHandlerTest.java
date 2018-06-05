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
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml2.core.impl.SubjectBuilder;
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
import org.wso2.carbon.base.CarbonBaseConstants;
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
import org.wso2.carbon.identity.base.IdentityException;
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
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuerImpl;
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
import java.nio.file.Paths;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.doNothing;
import static org.powermock.api.mockito.PowerMockito.doThrow;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

/**
 * tests for SAML2BearerGrantHandler
 */
@PowerMockIgnore({"javax.net.*"})
@PrepareForTest({IdentityUtil.class, IdentityTenantUtil.class, IdentityProviderManager.class, MultitenantUtils.class,
        IdentityApplicationManagementUtil.class, OAuthServerConfiguration.class, SSOServiceProviderConfigManager.class,
        SAML2BearerGrantHandler.class, OAuthComponentServiceHolder.class, OAuth2ServiceComponentHolder.class,
        OAuth2Util.class,})
public class SAML2BearerGrantHandlerTest extends PowerMockIdentityBaseTest {

    public static final String[] SCOPE_ARRAY = {"scope1"};
    private SAML2BearerGrantHandler saml2BearerGrantHandler;
    private Assertion assertion;
    private ServiceProvider serviceProvider;
    private FederatedAuthenticatorConfig samlConfig;
    private FederatedAuthenticatorConfig oauthConfig;
    private FederatedAuthenticatorConfig federatedAuthenticatorConfig;
    private OAuthTokenReqMessageContext tokReqMsgCtx;
    private OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO;
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

        System.setProperty(
                CarbonBaseConstants.CARBON_HOME,
                Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString()
        );
        mockStatic(OAuthServerConfiguration.class);
        mockStatic(IdentityUtil.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);
        when(oAuthServerConfiguration.getIdentityOauthTokenIssuer()).thenReturn(oauthIssuer);
        when(oAuthServerConfiguration.getPersistenceProcessor()).thenReturn(persistenceProcessor);
        federatedAuthenticatorConfig = new FederatedAuthenticatorConfig();
        saml2BearerGrantHandler = new SAML2BearerGrantHandler();
        saml2BearerGrantHandler.init();
        oAuth2AccessTokenReqDTO = new OAuth2AccessTokenReqDTO();
        oAuth2AccessTokenReqDTO.setScope(SCOPE_ARRAY);
        tokReqMsgCtx = new OAuthTokenReqMessageContext(oAuth2AccessTokenReqDTO);
        tokReqMsgCtx.setTenantID(-1234);
        oauthIssuer = new OauthTokenIssuerImpl();
    }

    @DataProvider (name = "provideValidData")
    public Object[][] provideValidData() {
        return new Object[][] {
                {OAuthConstants.UserType.FEDERATED_USER_DOMAIN_PREFIX, "LOCAL"},
                {OAuthConstants.UserType.LOCAL_USER_TYPE, "LOCAL"},
                {OAuthConstants.UserType.LEGACY_USER_TYPE, "LOCAL"},
                {"unknown", "LOCAL"},
                {"unknown", "FED"}
        };
    }

    @Test (dataProvider = "provideValidData")
    public void testValidateGrant(String userType, String idpName) throws Exception {

        initSAMLGrant(userType, idpName);
        mockOAuthComponents();
        when(realmService.getTenantUserRealm(anyInt())).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userStoreManager.isExistingUser(anyString())).thenReturn(true);
        when(oAuthServerConfiguration.getSaml2BearerTokenUserType()).thenReturn(userType);
        when(IdentityUtil.extractDomainFromName(anyString())).thenReturn(TestConstants.USERSTORE_DOMAIN);
        assertTrue(saml2BearerGrantHandler.validateGrant(tokReqMsgCtx));

        Assertion savedAsserion = (Assertion) tokReqMsgCtx.getProperty(OAuthConstants.OAUTH_SAML2_ASSERTION);
        assertEquals(savedAsserion, assertion, "Assertion not set in message context");
        assertEquals(tokReqMsgCtx.getScope(), SCOPE_ARRAY, "Scope not set in message context");
        assertNotNull(tokReqMsgCtx.getValidityPeriod(), "Validity period not set in message context");
        assertNotNull(tokReqMsgCtx.getAuthorizedUser(), "AuthorizedUser not set in message context");
        assertEquals(tokReqMsgCtx.getAuthorizedUser().getUserName(), MultitenantUtils.getTenantAwareUsername(TestConstants.TEST_USER_NAME));
    }

    @DataProvider (name = "validateGrantExceptionDataProvider")
    public Object[][] validateGrantExceptionDataProvider() throws Exception {

        NameID nameId1 = (new NameIDBuilder()).buildObject();
        nameId1.setValue("nameIdValue");
        Subject subject1 = (new SubjectBuilder()).buildObject();
        subject1.setNameID(nameId1);

        NameID nameId2 = (new NameIDBuilder()).buildObject();
        nameId2.setValue(null);
        Subject subject2 = (new SubjectBuilder()).buildObject();
        subject2.setNameID(nameId2);

        DateTime validOnOrAfter = new DateTime(System.currentTimeMillis() + 10000000L);
        DateTime expiredOnOrAfter = new DateTime(System.currentTimeMillis() - 10000000L);
        return new Object[][] {
                { validOnOrAfter, "LOCAL", true, true, TestConstants.OAUTH2_TOKEN_EP, TestConstants.LOACALHOST_DOMAIN, new IdentityException("Error"), "Error while unmashalling"},
                { validOnOrAfter, "FED", true, true, TestConstants.OAUTH2_TOKEN_EP, TestConstants.LOACALHOST_DOMAIN, new IdentityProviderManagementException("Error"), "Error while retrieving identity provider"},
                { validOnOrAfter, "FED", true, true, TestConstants.OAUTH2_TOKEN_EP, TestConstants.LOACALHOST_DOMAIN, new ValidationException(), "Error while validating the signature"},
                { validOnOrAfter, "LOCAL", true, true, TestConstants.OAUTH2_TOKEN_EP, TestConstants.LOACALHOST_DOMAIN, new IdentityApplicationManagementException("Error"), "Error while retrieving service provider"},
                { validOnOrAfter, "LOCAL", true, true, TestConstants.OAUTH2_TOKEN_EP, TestConstants.LOACALHOST_DOMAIN, new UserStoreException(), "Error while building local user"},
                { validOnOrAfter, "FED", true, true, TestConstants.OAUTH2_TOKEN_EP, TestConstants.LOACALHOST_DOMAIN, new CertificateException(), "Error occurred while decoding public certificate"},
                { validOnOrAfter, "LOCAL", true, false, TestConstants.OAUTH2_TOKEN_EP, TestConstants.LOACALHOST_DOMAIN, null, "User not found"},
                { validOnOrAfter, "LOCAL", false, true, TestConstants.OAUTH2_TOKEN_EP, TestConstants.LOACALHOST_DOMAIN, null, "Non SaaS app"},
                { validOnOrAfter, "LOCAL", true, true, "invalidAudience", TestConstants.LOACALHOST_DOMAIN, null, "Audience Restriction validation failed"},
                { validOnOrAfter, "LOCAL", true, true, "", TestConstants.LOACALHOST_DOMAIN, null, "Token Endpoint alias has not been configured"},
                { validOnOrAfter, "FED", true, true, "invalidAudience", TestConstants.LOACALHOST_DOMAIN, null, "Audience Restriction validation failed"},
                { validOnOrAfter, "LOCAL", false, true, TestConstants.OAUTH2_TOKEN_EP, "invalidEntityId", null, "Issuer verification failed"},
                { validOnOrAfter, "LOCAL", false, true, TestConstants.OAUTH2_TOKEN_EP, null, null, "Issuer verification failed"},
                { validOnOrAfter, null, true, true, TestConstants.OAUTH2_TOKEN_EP, TestConstants.LOACALHOST_DOMAIN, null, "Identity provider is null"},
                { expiredOnOrAfter, "LOCAL", true, true, TestConstants.OAUTH2_TOKEN_EP, TestConstants.LOACALHOST_DOMAIN, null, "Assertion is not valid"},
                { null, "LOCAL", true, true, TestConstants.OAUTH2_TOKEN_EP, TestConstants.LOACALHOST_DOMAIN, null, "Cannot find valid NotOnOrAfter"},
        };
    }

    @Test (dataProvider = "validateGrantExceptionDataProvider")
    public void testValidateGrantException(Object dateTimeObj, String idpName, boolean isSaas, boolean isUserExist,
                                           String audience, String idpEntityId, Exception e, String expected)
            throws Exception {

        DateTime notOnOrAfter = (DateTime) dateTimeObj;
        initAssertion(OAuthConstants.UserType.LEGACY_USER_TYPE, idpName, notOnOrAfter);
        IdentityProvider idp = initIdentityProviderManager(idpName, audience);
        initFederatedAuthConfig(idp);
        initSignatureValidator();
        mockOAuthComponents();
        serviceProvider.setSaasApp(isSaas);
        when(realmService.getTenantUserRealm(anyInt())).thenReturn(userRealm);
        when(identityProviderManager.getIdPByAuthenticatorPropertyValue(anyString(), anyString(), anyString(),
                anyString(), anyBoolean())).thenReturn(idp);
        when(IdentityApplicationManagementUtil.getProperty(oauthConfig.getProperties(),
                IdentityApplicationConstants.Authenticator.OIDC.OAUTH2_TOKEN_URL)).thenReturn(
                        getProperty(IdentityApplicationConstants.Authenticator.OIDC.OAUTH2_TOKEN_URL, audience));
        when(IdentityApplicationManagementUtil.getProperty(samlConfig.getProperties(),
                IdentityApplicationConstants.Authenticator.SAML2SSO.IDP_ENTITY_ID)).thenReturn(
                        getProperty("samlsso", idpEntityId));
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userStoreManager.isExistingUser(anyString())).thenReturn(isUserExist);

        if (e instanceof IdentityProviderManagementException) {
            when(identityProviderManager.getIdPByAuthenticatorPropertyValue(anyString(), anyString(), anyString(),
                    anyString(), anyBoolean())).thenThrow(e);
        } else if (e instanceof IdentityException) {
            when(IdentityUtil.unmarshall(anyString())).thenThrow(e);
        } else if (e instanceof ValidationException) {
            doThrow(e).when(signatureValidator).validate(any(Signature.class));
        } else if (e instanceof IdentityApplicationManagementException) {
            when(applicationManagementService.getServiceProviderByClientId(anyString(), anyString(), anyString()))
                    .thenThrow(e);
        } else if (e instanceof UserStoreException) {
            when(realmService.getTenantUserRealm(anyInt())).thenThrow(e);
        } else if (e instanceof CertificateException) {
            when(IdentityApplicationManagementUtil.decodeCertificate(anyString())).thenThrow(e);
        }
         try {
             saml2BearerGrantHandler.validateGrant(tokReqMsgCtx);
             fail("Expected error not thrown");
         } catch (IdentityOAuth2Exception ex) {
             assertTrue(ex.getMessage().contains(expected));
         }
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
        IdentityProvider identityProvider = getIdentityProvider("LOCAL", TestConstants.OAUTH2_TOKEN_EP);
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

    private Assertion buildAssertion(DateTime notOnOrAfter, String userType, String idpName) throws Exception {

        String username;
        if (OAuthConstants.UserType.FEDERATED_USER_DOMAIN_PREFIX.equals(userType) ||
                !IdentityApplicationConstants.RESIDENT_IDP_RESERVED_NAME.equals(idpName)) {
            username = TestConstants.TENANT_AWARE_USER_NAME;
        } else {
            username = TestConstants.TEST_USER_NAME;
        }
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
                TestConstants.LOACALHOST_DOMAIN, username);
        authnReqDTO.setNameIDFormat(TestConstants.SAMPLE_NAME_ID_FORMAT);
        authnReqDTO.setIssuer(TestConstants.LOACALHOST_DOMAIN);
        authnReqDTO.setRequestedAudiences(new String[]{TestConstants.OAUTH2_TOKEN_EP});
        assertion = SAMLSSOUtil.buildSAMLAssertion(authnReqDTO, notOnOrAfter, TestConstants.SESSION_ID);
        return assertion;
    }

    public static ClaimMapping buildClaimMapping(String claimUri) {

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

    private IdentityProvider getIdentityProvider(String name, String alias){

        if (name == null) {
            return null;
        }
        IdentityProvider identityProvider = new IdentityProvider();
        identityProvider.setIdentityProviderName(name);
        identityProvider.setAlias(alias);
        return identityProvider;
    }

    private IdentityProvider initIdentityProviderManager(String idpName, String alias) throws Exception {

        mockStatic(IdentityApplicationManagementUtil.class);
        IdentityProvider identityProviderIns = getIdentityProvider(idpName, alias);
        when(IdentityProviderManager.getInstance()).thenReturn(identityProviderManager);
        when(identityProviderManager
                .getIdPByAuthenticatorPropertyValue(anyString(), anyString(), anyString(), anyString(), anyBoolean()))
                .thenReturn(identityProviderIns);
        if (IdentityApplicationConstants.RESIDENT_IDP_RESERVED_NAME.equals(idpName)) {
            when(identityProviderManager.getResidentIdP(anyString())).thenReturn(identityProviderIns);
        }
        return identityProviderIns;
    }

    private void initFederatedAuthConfig(IdentityProvider identityProvider) {

        if (identityProvider != null) {
            oauthConfig = new FederatedAuthenticatorConfig();
            samlConfig = new FederatedAuthenticatorConfig();

            //IdentityProvider identityProvider = getIdentityProvider("FED");
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
    }

    private void initAssertion(String userType, String idpName, DateTime notOnOrAfter) throws Exception {

        assertion = buildAssertion(notOnOrAfter, userType, idpName);
        String assertionString = SAMLSSOUtil.marshall(assertion);
        assertionString = new String(Base64.encodeBase64(assertionString.getBytes(Charsets.UTF_8)), Charsets.UTF_8);
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

        when(IdentityApplicationManagementUtil.decodeCertificate(anyString()))
                .thenReturn(x509Certificate);
        whenNew(SignatureValidator.class).withArguments(any(X509Credential.class)).thenReturn(signatureValidator);
        doNothing().when(signatureValidator).validate(any(Signature.class));
    }

    private void initSAMLGrant(String userType, String idpName) throws Exception {

        initAssertion(userType, idpName, new DateTime(System.currentTimeMillis() + 10000000L));
        IdentityProvider idp = initIdentityProviderManager(idpName, TestConstants.OAUTH2_TOKEN_EP);
        initFederatedAuthConfig(idp);
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
