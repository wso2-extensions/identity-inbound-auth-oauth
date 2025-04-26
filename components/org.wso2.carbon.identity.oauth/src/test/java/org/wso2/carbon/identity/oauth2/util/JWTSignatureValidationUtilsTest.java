/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth2.util;

import org.mockito.MockedStatic;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.core.IdentityKeyStoreResolver;
import org.wso2.carbon.identity.core.util.IdentityKeyStoreResolverConstants;

import java.io.FileInputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertThrows;
import static org.wso2.carbon.base.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;

@Listeners(MockitoTestNGListener.class)
public class JWTSignatureValidationUtilsTest {

    private static final String SAMPLE_ENCODED_CERT =
            "MIIFnDCCA4SgAwIBAgIEdBUfHzANBgkqhkiG9w0BAQwFADBoMQswCQYDVQQGEwJM\n" +
                    "SzEQMA4GA1UECBMHV2VzdGVybjEQMA4GA1UEBxMHQ29sb21ibzENMAsGA1UEChME\n" +
                    "V1NPMjEMMAoGA1UECxMDSUFNMRgwFgYDVQQDEw9JbnRlcm1lZGlhdGUgQ0EwHhcN\n" +
                    "MjUwNDA0MTE0NjQ5WhcNMjcwNDA0MTE0NjQ5WjBjMQswCQYDVQQGEwJMSzEQMA4G\n" +
                    "A1UECBMHV2VzdGVybjEQMA4GA1UEBxMHQ29sb21ibzENMAsGA1UEChMEV1NPMjEM\n" +
                    "MAoGA1UECxMDSUFNMRMwEQYDVQQDEwpNeU9yZyBDZXJ0MIICIjANBgkqhkiG9w0B\n" +
                    "AQEFAAOCAg8AMIICCgKCAgEAgZ8BNQXXWkgbzHGQnJxdTt45GnYpmFerirG0GJlO\n" +
                    "bs1EOlb5EOz3xoyIs+/C+upJY+5qWrtzi6inAJiXVhfFzYioJ5ktw/FWWEzmfcfw\n" +
                    "KS63fnUTPDrJbchtzDPDnAYIhcZHOlVNN/CBKhkq3Er2gaJFMcQmEu/S2RCj5Z2w\n" +
                    "CL+OKNW1FIhyUNrf7ixIovxEYqWMkjyF/4xpHFlDEMUNoWKqhuejtiyUwPfzmymw\n" +
                    "fJsi29l1OMWfQO+nw87oBzVWZuMRATYYH1buUolFv40cIIE8A3J1LYK3bO5B3cFT\n" +
                    "eK0n0NO6nxqvdHYloVh4l2Uva9wxh2v7RsVLV4fcPACWcY6cF7uNh4LOWUPbjcc7\n" +
                    "xKskMerjB6P1anMRvnNBeEUsrPOuwRCjUBw3GLzZ1IfCpzBunNz89UFZzSpdiQL7\n" +
                    "fjrz2qULqM4WmVCn0AkSiVe6smeKdm4CcASgaOQaZbuK+mbtT6QK/A6TlgkArRlB\n" +
                    "3ATGsTa4PVkIh1KEWpFS2oodPMKYd4htmcpG3omrpNf/I8/0hqlAkJa+KGEm1ysw\n" +
                    "YaS3tWQCqoEYe3qlDp+n9oCM4FFOL6x5mMULP0YSFYzE+wN65A8H6s52OS8KYfRq\n" +
                    "xBOzcvd2a3Qlig3W/y2gMmMPng+F+zNX4UyxtXJX7o/Y7NlKhU7Y7Y8UHoAMDIW2\n" +
                    "rAcCAwEAAaNTMFEwHQYDVR0OBBYEFEj0pTQ4MKgYJE2lAf2VIG6CU363MA8GA1Ud\n" +
                    "EwQIMAYBAf8CAQAwHwYDVR0jBBgwFoAUw+Fp6ES+VVn2zB9OknrySzGONxswDQYJ\n" +
                    "KoZIhvcNAQEMBQADggIBAERhvsJwFDo2dUGqwpyYI9tl0Hic5i7kl19eUf0uJRHY\n" +
                    "vb2syusa/LEq7Ne2MEvPUYe7fNEC14vqFVKjqPiR2/k0VW/kWQgrLMM8uhsVDdpm\n" +
                    "iPaC1Xif/no5EjGSJes2N1Wg8nCRl/SzotyzOIor819kcCI6O3vAMehD70YZbCZ2\n" +
                    "ma50EvqJUddOxWwaGzE7yNFTCrxyjniLTochWTrrupK2lEX1WsmUefvm87+Ceyjg\n" +
                    "ryWxFfgGJ6y/Mrg9Mice+95EIMFRakX2cPgtDRfsecTgvlofQLFU6gmxEv3GhGoP\n" +
                    "xtIuyB5F/Bw1SE4wIvLkY6otx7UvvZRBRExiQ069weuqGKlOHqvT8jckaTRXslu/\n" +
                    "67LsGAiuGrctSSA6mRYmZoLDad/jWCW957FwJ8im1yJEWFY6v3u0Nd6K312530Y0\n" +
                    "FpHFWplrgiFM6XNbCsVJB7cNcJF2wS8hthnxd3xw7ClZsJmWJAu7UI1b/NoojJ7l\n" +
                    "3pDI4B+vQipcfTjJqgPAWvUz903z61lRuAlJFPPD69l+IQ15z1Mfc7rgl0wmZLBU\n" +
                    "HjVlGsFGQX6e10Rx/msN+NWxKJGf7Z6vxS8Qoc4nddUBnndCOvCVvgI9BThNv0cG\n" +
                    "e3hB2nvCQvUJ/wfuj6i1PNfoM81nA2qEQfjY/QWuF4Ex/RYWBfASNU35TBRVc26R";

    private PrivilegedCarbonContext privilegedCarbonContext;

    private MockedStatic<IdentityKeyStoreResolver> identityKeyStoreResolverMockedStatic;
    private MockedStatic<PrivilegedCarbonContext> privilegedCarbonContextMockedStatic;

    @BeforeClass
    public void setUp() throws Exception {

        System.setProperty(CarbonBaseConstants.CARBON_HOME,
                Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString());
        privilegedCarbonContextMockedStatic = mockStatic(PrivilegedCarbonContext.class);
        privilegedCarbonContext = mock(PrivilegedCarbonContext.class);
        privilegedCarbonContextMockedStatic.when(PrivilegedCarbonContext::getThreadLocalCarbonContext)
                .thenReturn(privilegedCarbonContext);
        mockKeystores();
    }

    @AfterClass
    public void tearDown() {

        identityKeyStoreResolverMockedStatic.close();
        privilegedCarbonContextMockedStatic.close();
    }

    @Test(description = "Test the resolveSignerCertificate method")
    public void testResolveSignerCertificate() throws Exception {

        when(privilegedCarbonContext.getTenantDomain()).thenReturn(SUPER_TENANT_DOMAIN_NAME);
        IdentityProvider identityProvider = mock(IdentityProvider.class);

        // Test the resident IDP certificate.
        when(identityProvider.getIdentityProviderName()).thenReturn(
                IdentityApplicationConstants.RESIDENT_IDP_RESERVED_NAME);
        X509Certificate certificate = JWTSignatureValidationUtils.resolveSignerCertificate(null, identityProvider);
        assertEquals(certificate.getIssuerDN().getName(), "CN=localhost, O=WSO2, L=Mountain View, ST=CA, C=US");
        when(privilegedCarbonContext.getTenantDomain()).thenReturn(null);
        certificate = JWTSignatureValidationUtils.resolveSignerCertificate(null, identityProvider);
        assertEquals(certificate.getIssuerDN().getName(), "CN=localhost, O=WSO2, L=Mountain View, ST=CA, C=US");

        // Test the secondary IDP certificate.
        when(identityProvider.getIdentityProviderName()).thenReturn("test-idp");
        when(identityProvider.getCertificate()).thenReturn(SAMPLE_ENCODED_CERT);
        certificate = JWTSignatureValidationUtils.resolveSignerCertificate(null, identityProvider);
        assertEquals(certificate.getIssuerDN().getName(),
                "CN=Intermediate CA, OU=IAM, O=WSO2, L=Colombo, ST=Western, C=LK");

        // Test the exception when the certificate is not found.
        when(identityProvider.getCertificate()).thenReturn(null);
        assertThrows(() -> JWTSignatureValidationUtils.resolveSignerCertificate(null, identityProvider));
    }

    private void mockKeystores() throws Exception {

        IdentityKeyStoreResolver identityKeyStoreResolver = mock(IdentityKeyStoreResolver.class);
        KeyStore keyStore = getKeyStoreFromFile("wso2carbon.jks", "wso2carbon",
                System.getProperty(CarbonBaseConstants.CARBON_HOME));
        when(identityKeyStoreResolver.getKeyStore(SUPER_TENANT_DOMAIN_NAME,
                IdentityKeyStoreResolverConstants.InboundProtocol.OAUTH)).thenReturn(keyStore);
        when(identityKeyStoreResolver.getCertificate(SUPER_TENANT_DOMAIN_NAME,
                IdentityKeyStoreResolverConstants.InboundProtocol.OAUTH)).thenReturn(
                keyStore.getCertificate("wso2carbon"));
        when(identityKeyStoreResolver.getPrivateKey(SUPER_TENANT_DOMAIN_NAME,
                IdentityKeyStoreResolverConstants.InboundProtocol.OAUTH)).thenReturn(
                keyStore.getKey("wso2carbon", "wso2carbon".toCharArray()));

        identityKeyStoreResolverMockedStatic = mockStatic(IdentityKeyStoreResolver.class);
        identityKeyStoreResolverMockedStatic.when(IdentityKeyStoreResolver::getInstance)
                .thenReturn(identityKeyStoreResolver);
    }

    private KeyStore getKeyStoreFromFile(String keystoreName, String password,
                                         String home) throws Exception {

        Path tenantKeystorePath = Paths.get(home, "repository", "resources", "security", keystoreName);
        FileInputStream file = new FileInputStream(tenantKeystorePath.toString());
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(file, password.toCharArray());
        return keystore;
    }
}
