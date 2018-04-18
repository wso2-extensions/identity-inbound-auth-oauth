/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.reflect.internal.WhiteboxImpl;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.base.api.ServerConfigurationService;
import org.wso2.carbon.core.internal.CarbonCoreDataHolder;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth2.TestConstants;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.idp.mgt.internal.IdpMgtServiceComponentHolder;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;
import org.xml.sax.SAXException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.powermock.api.mockito.PowerMockito.doNothing;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.testng.Assert.assertTrue;
import static org.testng.AssertJUnit.assertEquals;

@WithCarbonHome
@PrepareForTest({IdentityUtil.class, OAuth2Util.class, IdentityProviderManager.class, IdentityApplicationManagementUtil.class})
public class SAML1BearerGrantHandlerTest extends PowerMockIdentityBaseTest {

    private static final String ISSUER1 = "idp1";
    private static final String ISSUER2 = "LOCAL";
    private static final String NOT_ON_OR_AFTER1 = "2002-06-19T17:10:37.795Z";
    private static final String NOT_ON_OR_AFTER2 = new DateTime().toString();
    private static final String CERTIFICATE =
            "MIICNTCCAZ6gAwIBAgIES343gjANBgkqhkiG9w0BAQUFADBVMQswCQYDVQQGEwJVUzELMAkGA1UE\n" +
                    "CAwCQ0ExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxDTALBgNVBAoMBFdTTzIxEjAQBgNVBAMMCWxv\n" +
                    "Y2FsaG9zdDAeFw0xMDAyMTkwNzAyMjZaFw0zNTAyMTMwNzAyMjZaMFUxCzAJBgNVBAYTAlVTMQsw\n" +
                    "CQYDVQQIDAJDQTEWMBQGA1UEBwwNTW91bnRhaW4gVmlldzENMAsGA1UECgwEV1NPMjESMBAGA1UE\n" +
                    "AwwJbG9jYWxob3N0MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCUp/oV1vWc8/TkQSiAvTou\n" +
                    "sMzOM4asB2iltr2QKozni5aVFu818MpOLZIr8LMnTzWllJvvaA5RAAdpbECb+48FjbBe0hseUdN5\n" +
                    "HpwvnH/DW8ZccGvk53I6Orq7hLCv1ZHtuOCokghz/ATrhyPq+QktMfXnRS4HrKGJTzxaCcU7OQID\n" +
                    "AQABoxIwEDAOBgNVHQ8BAf8EBAMCBPAwDQYJKoZIhvcNAQEFBQADgYEAW5wPR7cr1LAdq+IrR44i\n" +
                    "QlRG5ITCZXY9hI0PygLP2rHANh+PYfTmxbuOnykNGyhM6FjFLbW2uZHQTY1jMrPprjOrmyK5sjJR\n" +
                    "O4d1DeGHT/YnIjs9JogRKv4XHECwLtIVdAbIdWHEtVZJyMSktcyysFcvuhPQK8Qc/E/Wq8uHSCo=";
    private static String assertion =
            "  <saml:Assertion\n" +
                    "    xmlns:saml=\"urn:oasis:names:tc:SAML:1.0:assertion\"\n" +
                    "    MajorVersion=\"1\" MinorVersion=\"1\"\n" +
                    "    AssertionID=\"buGxcG4gILg5NlocyLccDz6iXrUa\"\n" +
                    "    Issuer=\"" + ISSUER1 + "\"\n" +
                    "    IssueInstant=\"2002-06-19T17:05:37.795Z\">\n" +
                    "    <saml:Conditions\n" +
                    "      NotBefore=\"2002-06-19T17:00:37.795Z\"\n" +
                    "      NotOnOrAfter=\"" + NOT_ON_OR_AFTER1 + "\">\n" +
                    "      <saml:AudienceRestrictionCondition>\n" +
                    "           <saml:Audience>https://sp.example.com/samlsso</saml:Audience>\n" +
                    "      </saml:AudienceRestrictionCondition>\n" +
                    "    </saml:Conditions>\n" +
                    "    <saml:AuthenticationStatement\n" +
                    "      AuthenticationMethod=\"urn:oasis:names:tc:SAML:1.0:am:password\"\n" +
                    "      AuthenticationInstant=\"2002-06-19T17:05:17.706Z\">\n" +
                    "      <saml:Subject>\n" +
                    "        <saml:NameIdentifier\n" +
                    "          Format=\"urn:oasis:names:tc:SAML:1.0:assertion#emailAddress\">\n" +
                    "          user@" + ISSUER1 + "\n" +
                    "        </saml:NameIdentifier>\n" +
                    "        <saml:SubjectConfirmation>\n" +
                    "          <saml:ConfirmationMethod>\n" +
                    "            urn:oasis:names:tc:SAML:1.0:cm:bearer\n" +
                    "          </saml:ConfirmationMethod>\n" +
                    "        </saml:SubjectConfirmation>\n" +
                    "      </saml:Subject>\n" +
                    "    </saml:AuthenticationStatement>\n" +
                    "    <ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                    "            <ds:SignedInfo>\n" +
                    "                <ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\" />\n" +
                    "                <ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\" />\n" +
                    "                <ds:Reference URI=\"#buGxcG4gILg5NlocyLccDz6iXrUa\">\n" +
                    "                    <ds:Transforms>\n" +
                    "                        <ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\" />\n" +
                    "                        <ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\" />\n" +
                    "                    </ds:Transforms>\n" +
                    "                    <ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\" />\n" +
                    "                    <ds:DigestValue>FNB5TA/klWcRpdAIx4sBaANSnsg=</ds:DigestValue>\n" +
                    "                </ds:Reference>\n" +
                    "            </ds:SignedInfo>\n" +
                    "            <ds:SignatureValue>\n" +
                    "               kRL6SR/6zWqmndMzgsSaOwPNqXpgIZ193PcHBto5tYtOwKMpDs0dgpS/79h+jwuhZxVfuZ9U64gB\n" +
                    "               uwBfE3xjALYutF7f20aWQ9E3s7tWyI81RxLU6LtyyFveUCcRAzqvEfPu8w4qqOITJvl3zlTIBJ9x\n" +
                    "               d+Y4cWt54SmI66XT54g=\n" +
                    "            </ds:SignatureValue>\n" +
                    "           <ds:KeyInfo>\n" +
                    "            <ds:X509Data>\n" +
                    "                <ds:X509Certificate>" +
                    CERTIFICATE +
                    "                </ds:X509Certificate>\n" +
                    "            </ds:X509Data>\n" +
                    "        </ds:KeyInfo>\n" +
                    "    </ds:Signature>" +
                    "  </saml:Assertion>";
    private SAML1BearerGrantHandler saml1BearerGrantHandler;

    @DataProvider(name = "BuildAssertion")
    public static Object[][] buildAssertion() {

        return new Object[][]{
                {StringUtils.EMPTY, false, false},
                {assertion, false, false},
                {assertion.replace(ISSUER1, ISSUER2), false, false},
                {StringUtils.EMPTY, true, false},
                {assertion, true, false},
                {assertion.replace(ISSUER1, ISSUER2), true, false},

                {StringUtils.EMPTY, false, false},
                {assertion.replace(NOT_ON_OR_AFTER1, NOT_ON_OR_AFTER2), false, false},
                {(assertion.replace(NOT_ON_OR_AFTER1, NOT_ON_OR_AFTER2)).replace(ISSUER1, ISSUER2), false, false},
                {StringUtils.EMPTY, true, false},
                {assertion.replace(NOT_ON_OR_AFTER1, NOT_ON_OR_AFTER2), true, false},
                {(assertion.replace(NOT_ON_OR_AFTER1, NOT_ON_OR_AFTER2)).replace(ISSUER1, ISSUER2), true, false}
        };
    }

    @BeforeMethod
    public void setUp() throws Exception {

        saml1BearerGrantHandler = new SAML1BearerGrantHandler();
    }

    @Test
    public void testInit() throws Exception {

        saml1BearerGrantHandler = spy(saml1BearerGrantHandler);
        saml1BearerGrantHandler.init();
        verify(saml1BearerGrantHandler).init();
    }

    @Test(dataProvider = "BuildAssertion")
    public void testValidateGrant(String assertion, boolean enableAudienceRestriction, boolean expectedResult)
            throws Exception {

        OAuthTokenReqMessageContext oAuthTokenReqMessageContext = buildOAuth2AccessTokenReqDTO();
        RequestParameter[] requestParameters = new RequestParameter[]{new RequestParameter("assertion",
                Base64.encodeBase64String(assertion.getBytes()))};
        DefaultBootstrap.bootstrap();
        oAuthTokenReqMessageContext.getOauth2AccessTokenReqDTO().setRequestParameters(requestParameters);
        WhiteboxImpl.setInternalState(saml1BearerGrantHandler, "audienceRestrictionValidationEnabled",
                enableAudienceRestriction);
        RealmService realmService = mock(RealmService.class);
        RegistryService registryService = mock(RegistryService.class);
        ServerConfigurationService serverConfigurationService = mock(ServerConfigurationService.class);
        CarbonCoreDataHolder.getInstance().setRegistryService(registryService);
        CarbonCoreDataHolder.getInstance().setServerConfigurationService(serverConfigurationService);
        TenantManager tenantManager = mock(TenantManager.class);
        when(realmService.getTenantManager()).thenReturn(tenantManager);
        when(tenantManager.getTenantId(TestConstants.CARBON_TENANT_DOMAIN)).thenReturn(MultitenantConstants.
                SUPER_TENANT_ID);
        IdpMgtServiceComponentHolder.getInstance().setRealmService(realmService);

        KeyStoreManager keyStoreManager = mock(KeyStoreManager.class);
        ConcurrentHashMap<String, KeyStoreManager> mtKeyStoreManagers = new ConcurrentHashMap();
        mtKeyStoreManagers.put("-1234", keyStoreManager);
        WhiteboxImpl.setInternalState(KeyStoreManager.class, "mtKeyStoreManagers", mtKeyStoreManagers);
        X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
                new ByteArrayInputStream(Base64.decodeBase64(CERTIFICATE)));
        when(keyStoreManager.getDefaultPrimaryCertificate()).thenReturn(cert);
        Map<String, Object> configuration = new HashMap<>();
        configuration.put("SSOService.EntityId", "LOCAL");
        WhiteboxImpl.setInternalState(IdentityUtil.class, "configuration", configuration);
        saml1BearerGrantHandler.profileValidator = new SAMLSignatureProfileValidator();

        this.mockAuthenticatedUser();
        this.mockIdentityProvider(assertion);
        this.mockX509Certificate(cert);

        if (!assertion.equals("")) {
            XMLObject xmlObject = this.unmarshall(assertion);
            PowerMockito.stub(PowerMockito.method(IdentityUtil.class, "unmarshall")).toReturn(xmlObject);
        }

        assertEquals(saml1BearerGrantHandler.validateGrant(oAuthTokenReqMessageContext), expectedResult);
        WhiteboxImpl.setInternalState(IdentityUtil.class, "configuration", new HashMap<>());
    }

    @Test
    public void testValidateScope() throws Exception {

        assertTrue(saml1BearerGrantHandler.validateScope(buildOAuth2AccessTokenReqDTO()));
    }

    @Test
    public void testAuthorizeAccessDelegation() throws Exception {

        assertTrue(saml1BearerGrantHandler.authorizeAccessDelegation(buildOAuth2AccessTokenReqDTO()));
    }

    @Test
    public void testIssueRefreshToken() throws Exception {

        assertTrue(saml1BearerGrantHandler.issueRefreshToken());
    }

    private OAuthTokenReqMessageContext buildOAuth2AccessTokenReqDTO() {

        OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO = new OAuth2AccessTokenReqDTO();
        OAuthTokenReqMessageContext oAuthTokenReqMessageContext = new OAuthTokenReqMessageContext(
                oAuth2AccessTokenReqDTO);
        return oAuthTokenReqMessageContext;
    }

    private void mockAuthenticatedUser() throws Exception {

        AuthenticatedUser authenticatedUser = mock(AuthenticatedUser.class);
        doNothing().when(authenticatedUser).setAuthenticatedSubjectIdentifier(anyString());
        doNothing().when(authenticatedUser).setFederatedUser(true);
        mockStatic(OAuth2Util.class);
        when(OAuth2Util.getUserFromUserName(anyString())).thenReturn(authenticatedUser);
    }

    private void mockIdentityProvider(String assertion) throws Exception {

        IdentityProvider identityProvider = mock(IdentityProvider.class);
        when(identityProvider.getAlias()).thenReturn("https://sp.example.com/samlsso");
        if (assertion.contains(ISSUER1)) {
            when(identityProvider.getIdentityProviderName()).thenReturn(ISSUER1);
        } else {
            when(identityProvider.getIdentityProviderName()).thenReturn(ISSUER2);
        }

        IdentityProviderManager identityProviderManager = mock(IdentityProviderManager.class);
        mockStatic(IdentityProviderManager.class);
        when(identityProviderManager.getIdPByAuthenticatorPropertyValue(anyString(), anyString(),
                anyString(), anyBoolean())).thenReturn(identityProvider);
        when(identityProviderManager.getResidentIdP(anyString())).thenReturn(identityProvider);
        when(IdentityProviderManager.getInstance()).thenReturn(identityProviderManager);

        this.mockAuthenticators(identityProvider);

    }

    private void mockAuthenticators(IdentityProvider identityProvider) {

        FederatedAuthenticatorConfig federatedAuthenticatorConfigObject = mock(FederatedAuthenticatorConfig.class);
        Property propertyObjectName = mock(Property.class);
        Property propertyObecctUrl = mock(Property.class);
        FederatedAuthenticatorConfig[] federatedAuthenticatorConfigs = {federatedAuthenticatorConfigObject};
        Property[] properties = {propertyObjectName, propertyObecctUrl};
        when(identityProvider.getFederatedAuthenticatorConfigs()).thenReturn(federatedAuthenticatorConfigs);
        when(federatedAuthenticatorConfigObject.getProperties()).thenReturn(properties);

        mockStatic(IdentityApplicationManagementUtil.class);
        when(IdentityApplicationManagementUtil.getFederatedAuthenticator(any(), anyString()))
                .thenReturn(federatedAuthenticatorConfigObject);
        when(IdentityApplicationManagementUtil
                .getProperty(properties, IdentityApplicationConstants.Authenticator.OIDC.NAME))
                .thenReturn(propertyObjectName);
        when(IdentityApplicationManagementUtil
                .getProperty(properties, IdentityApplicationConstants.Authenticator.OIDC.OAUTH2_TOKEN_URL))
                .thenReturn(propertyObjectName);
        when(propertyObjectName.getValue()).thenReturn("LOCAL");
        when(propertyObecctUrl.getValue()).thenReturn("https://sp.example.com/samlsso");
    }

    private void mockX509Certificate(X509Certificate cert) throws CertificateException {

        when(IdentityApplicationManagementUtil.decodeCertificate(anyString()))
                .thenReturn(cert);
    }

    private XMLObject unmarshall(String samlString) {

        XMLObject xmlObject = null;
        try {
            DocumentBuilderFactory documentBuilderFactory = IdentityUtil.getSecuredDocumentBuilderFactory();
            documentBuilderFactory.setIgnoringComments(true);
            DocumentBuilder docBuilder = documentBuilderFactory.newDocumentBuilder();
            ByteArrayInputStream inputStream = new ByteArrayInputStream(samlString.getBytes());
            Document document = docBuilder.parse(inputStream);
            Element element = document.getDocumentElement();
            UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
            Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
            xmlObject = unmarshaller.unmarshall(element);
        } catch (UnmarshallingException | SAXException | IOException | ParserConfigurationException e) {
            String message = "Error in constructing XML Object from the encoded String";

        }
        return xmlObject;

    }

}
