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

package org.wso2.carbon.identity.discovery;

import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

import java.util.Map;

import static org.testng.Assert.assertEquals;

public class OIDProviderConfigResponseTest {

    private OIDProviderConfigResponse oidProviderConfigResponse = new OIDProviderConfigResponse();

    @BeforeTest
    public void setUp() throws Exception {
    }

    @AfterMethod
    public void tearDown() throws Exception {
    }

    @Test
    public void testGetandSetIssuer() throws Exception {
        String issuer = "issuer";
        oidProviderConfigResponse.setIssuer("issuer");
        String issuer1 = oidProviderConfigResponse.getIssuer();
        assertEquals(issuer1, issuer);
    }

    @Test
    public void testGetandSetAuthorizationEndpoint() throws Exception {
        String authorizationEndpoint = "authorizationEndpoint";
        oidProviderConfigResponse.setAuthorizationEndpoint("authorizationEndpoint");
        String authorizationEndpoint1 = oidProviderConfigResponse.getAuthorizationEndpoint();
        assertEquals(authorizationEndpoint1, authorizationEndpoint);
    }

    @Test
    public void testGetandSetTokenEndpoint() throws Exception {
        String tokenEndpoint = "tokenEndpoint";
        oidProviderConfigResponse.setTokenEndpoint("tokenEndpoint");
        String tokenEndpoint1 = oidProviderConfigResponse.getTokenEndpoint();
        assertEquals(tokenEndpoint1, tokenEndpoint);
    }

    @Test
    public void testGetandSetUserinfoEndpoint() throws Exception {
        String userinfoEndpont = "userinfoEndpont";
        oidProviderConfigResponse.setUserinfoEndpoint("userinfoEndpont");
        String userinfoEndpoint1 = oidProviderConfigResponse.getUserinfoEndpoint();
        assertEquals(userinfoEndpoint1, userinfoEndpont);
    }

    @Test
    public void testGetandSetJwksUri() throws Exception {
        String jwksUri = "jwksUri";
        oidProviderConfigResponse.setJwksUri("jwksUri");
        String jwksUri1 = oidProviderConfigResponse.getJwksUri();
        assertEquals(jwksUri1, jwksUri);
    }

    @Test
    public void testGetandSetRegistrationEndpoint() throws Exception {
        String registrationEndpoint = "registrationEndpoint";
        oidProviderConfigResponse.setRegistrationEndpoint("registrationEndpoint");
        String registrationEndpoint1 = oidProviderConfigResponse.getRegistrationEndpoint();
        assertEquals(registrationEndpoint1, registrationEndpoint);
    }

    @Test
    public void testGetandSetScopesSupported() throws Exception {
        String scopesSupported[] = {"scope1", "scope2"};
        oidProviderConfigResponse.setScopesSupported(new String[]{"scope1", "scope2"});
        String scopesSupported1[] = oidProviderConfigResponse.getScopesSupported();
        assertEquals(scopesSupported1, scopesSupported);
    }

    @Test
    public void testGetResponseTypesSupported() throws Exception {
        String responseTypesSupported[] = {"type1", "type2"};
        oidProviderConfigResponse.setResponseTypesSupported(new String[]{"type1", "type2"});
        String responseTypesSupported1[] = oidProviderConfigResponse.getResponseTypesSupported();
        assertEquals(responseTypesSupported1, responseTypesSupported);
    }

    @Test
    public void testGetandSetResponseModesSupported() throws Exception {
        String responseModesSupported[] = {"mode1", "mode2"};
        oidProviderConfigResponse.setResponseModesSupported(new String[]{"mode1", "mode2"});
        String responseModesSupported1[] = oidProviderConfigResponse.getResponseModesSupported();
        assertEquals(responseModesSupported1, responseModesSupported);
    }

    @Test
    public void testGetandSetGrantTypesSupported() throws Exception {
        String grantTypesSupported[] = {"type1", "type2"};
        oidProviderConfigResponse.setGrantTypesSupported(new String[]{"type1", "type2"});
        String grantTypesSupported1[] = oidProviderConfigResponse.getGrantTypesSupported();
        assertEquals(grantTypesSupported1, grantTypesSupported);
    }

    @Test
    public void testGetandSetAcrValuesSupported() throws Exception {
        String acrValuesSupported[] = {"value1", "value2"};
        oidProviderConfigResponse.setAcrValuesSupported(new String[]{"value1", "value2"});
        String acrValuesSupported1[] = oidProviderConfigResponse.getAcrValuesSupported();
        assertEquals(acrValuesSupported1, acrValuesSupported);
    }

    @Test
    public void testGetandSetSubjectTypesSupported() throws Exception {
        String subjectTypesSupported[] = {"type1", "type2"};
        oidProviderConfigResponse.setSubjectTypesSupported(new String[]{"type1", "type2"});
        String subjectTypesSupported1[] = oidProviderConfigResponse.getSubjectTypesSupported();
        assertEquals(subjectTypesSupported1, subjectTypesSupported);
    }

    @Test
    public void testGetandSetIdTokenSigningAlgValuesSupported() throws Exception {
        String idTokenSigningAlgValuesSupported[] = {"value1", "value2"};
        oidProviderConfigResponse.setIdTokenSigningAlgValuesSupported(new String[]{"value1", "value2"});
        String idTokenSigningAlgValuesSupported1[] = oidProviderConfigResponse.getIdTokenSigningAlgValuesSupported();
        assertEquals(idTokenSigningAlgValuesSupported1, idTokenSigningAlgValuesSupported);
    }

    @Test
    public void testGetandSetIdTokenEncryptionAlgValuesSupported() throws Exception {
        String idTokenEncryptionAlgValuesSupported[] = {"value1", "value2"};
        oidProviderConfigResponse.setIdTokenEncryptionAlgValuesSupported(new String[]{"value1", "value2"});
        String idTokenEncryptionAlgValuesSupported1[] = oidProviderConfigResponse.
                getIdTokenEncryptionAlgValuesSupported();
        assertEquals(idTokenEncryptionAlgValuesSupported1, idTokenEncryptionAlgValuesSupported);
    }

    @Test
    public void testGetandSetIdTokenEncryptionEncValuesSupported() throws Exception {
        String idTokenEncryptionEncValuesSupported[] = {"value1", "value2"};
        oidProviderConfigResponse.setIdTokenEncryptionEncValuesSupported(new String[]{"value1", "value2"});
        String idTokenEncryptionEncValuesSupported1[] = oidProviderConfigResponse.
                getIdTokenEncryptionEncValuesSupported();
        assertEquals(idTokenEncryptionEncValuesSupported1, idTokenEncryptionEncValuesSupported);
    }

    @Test
    public void testGetandSetUserinfoSigningAlgValuesSupported() throws Exception {
        String userinfoSigningAlgValuesSupported[] = {"value1", "value2"};
        oidProviderConfigResponse.setUserinfoSigningAlgValuesSupported(new String[]{"value1", "value2"});
        String userinfoSigningAlgValuesSupported1[] = oidProviderConfigResponse.getUserinfoSigningAlgValuesSupported();
        assertEquals(userinfoSigningAlgValuesSupported1, userinfoSigningAlgValuesSupported);
    }

    @Test
    public void testGetandSetUserinfoEncryptionAlgValuesSupported() throws Exception {
        String userinfoEncryptionAlgValuesSupported[] = {"value1", "value2"};
        oidProviderConfigResponse.setUserinfoEncryptionAlgValuesSupported(new String[]{"value1", "value2"});
        String userinfoEncryptionAlgValuesSupported1[] = oidProviderConfigResponse.
                getUserinfoEncryptionAlgValuesSupported();
        assertEquals(userinfoEncryptionAlgValuesSupported1, userinfoEncryptionAlgValuesSupported);
    }

    @Test
    public void testGetandSetUserinfoEncryptionEncValuesSupported() throws Exception {
        String userinfoEncryptionEncValuesSupported[] = {"value1", "value2"};
        oidProviderConfigResponse.setUserinfoEncryptionEncValuesSupported(new String[]{"value1", "value2"});
        String userinfoEncryptionEncValuesSupported1[] = oidProviderConfigResponse.
                getUserinfoEncryptionEncValuesSupported();
        assertEquals(userinfoEncryptionEncValuesSupported1, userinfoEncryptionEncValuesSupported);
    }

    @Test
    public void testGetandSetRequestObjectSigningAlgValuesSupported() throws Exception {
        String requestObjectSigningAlgValuesSupported[] = {"value1", "value2"};
        oidProviderConfigResponse.setRequestObjectSigningAlgValuesSupported(new String[]{"value1", "value2"});
        String requestObjectSigningAlgValuesSupported1[] = oidProviderConfigResponse.
                getRequestObjectSigningAlgValuesSupported();
        assertEquals(requestObjectSigningAlgValuesSupported1, requestObjectSigningAlgValuesSupported);
    }

    @Test
    public void testGetandSetRequestObjectEncryptionAlgValuesSupported() throws Exception {
        String requestObjectEncryptionAlgValuesSupported[] = {"value1", "value2"};
        oidProviderConfigResponse.setRequestObjectEncryptionAlgValuesSupported(new String[]{"value1", "value2"});
        String requestObjectEncryptionAlgValuesSupported1[] = oidProviderConfigResponse.
                getRequestObjectEncryptionAlgValuesSupported();
        assertEquals(requestObjectEncryptionAlgValuesSupported1, requestObjectEncryptionAlgValuesSupported);
    }

    @Test
    public void testGetandSetRequestObjectEncryptionEncValuesSupported() throws Exception {
        String requestObjectEncryptionEncValuesSupported[] = {"value1", "value2"};
        oidProviderConfigResponse.setRequestObjectEncryptionEncValuesSupported(new String[]{"value1", "value2"});
        String requestObjectEncryptionEncValuesSupported1[] = oidProviderConfigResponse.
                getRequestObjectEncryptionEncValuesSupported();
        assertEquals(requestObjectEncryptionEncValuesSupported1, requestObjectEncryptionEncValuesSupported);
    }

    @Test
    public void testGetandSetTokenEndpointAuthMethodsSupported() throws Exception {
        String tokenEndpointAuthMethodsSupported[] = {"method1", "method2"};
        oidProviderConfigResponse.setTokenEndpointAuthMethodsSupported(new String[]{"method1", "method2"});
        String tokenEndpointAuthMethodsSupported1[] = oidProviderConfigResponse.
                getTokenEndpointAuthMethodsSupported();
        assertEquals(tokenEndpointAuthMethodsSupported1, tokenEndpointAuthMethodsSupported);
    }

    @Test
    public void testGetandSetTokenEndpointAuthSigningAlgValuesSupported() throws Exception {
        String tokenEndpointAuthSigningAlgValuesSupported[] = {"value1", "value2"};
        oidProviderConfigResponse.setTokenEndpointAuthSigningAlgValuesSupported(new String[]{"value1", "value2"});
        String tokenEndpointAuthSigningAlgValuesSupported1[] = oidProviderConfigResponse.
                getTokenEndpointAuthSigningAlgValuesSupported();
        assertEquals(tokenEndpointAuthSigningAlgValuesSupported1, tokenEndpointAuthSigningAlgValuesSupported);
    }

    @Test
    public void testGetandSetDisplayValuesSupported() throws Exception {
        String displayValuesSupported[] = {"value1", "value2"};
        oidProviderConfigResponse.setDisplayValuesSupported(new String[]{"value1", "value2"});
        String displayValuesSupported1[] = oidProviderConfigResponse.
                getDisplayValuesSupported();
        assertEquals(displayValuesSupported1, displayValuesSupported);
    }

    @Test
    public void testGetandSetClaimTypesSupported() throws Exception {
        String claimTypesSupported[] = {"type1", "type2"};
        oidProviderConfigResponse.setClaimTypesSupported(new String[]{"type1", "type2"});
        String claimTypesSupported1[] = oidProviderConfigResponse.getClaimTypesSupported();
        assertEquals(claimTypesSupported1, claimTypesSupported);
    }

    @Test
    public void testGetandSetClaimsSupported() throws Exception {
        String claimsSupported[] = {"claim1", "claim2"};
        oidProviderConfigResponse.setClaimsSupported(new String[]{"claim1", "claim2"});
        String claimsSupported1[] = oidProviderConfigResponse.getClaimsSupported();
        assertEquals(claimsSupported1, claimsSupported);
    }

    @Test
    public void testGetandSetServiceDocumentation() throws Exception {
        String serviceDocumentation = "serviceDocumentation";
        oidProviderConfigResponse.setServiceDocumentation("serviceDocumentation");
        String serviceDocumentation1 = oidProviderConfigResponse.getServiceDocumentation();
        assertEquals(serviceDocumentation1, serviceDocumentation);
    }

    @Test
    public void testGetandSetClaimsLocalesSupported() throws Exception {
        String claimsLocalesSupported[] = {"claim1", "claim2"};
        oidProviderConfigResponse.setClaimsLocalesSupported(new String[]{"claim1", "claim2"});
        String claimsLocalesSupported1[] = oidProviderConfigResponse.getClaimsLocalesSupported();
        assertEquals(claimsLocalesSupported1, claimsLocalesSupported);
    }

    @Test
    public void testGetandSetUiLocalesSupported() throws Exception {
        String uiLocalesSupported[] = {"ui1", "ui2"};
        oidProviderConfigResponse.setUiLocalesSupported(new String[]{"ui1", "ui2"});
        String uiLocalesSupported1[] = oidProviderConfigResponse.getUiLocalesSupported();
        assertEquals(uiLocalesSupported1, uiLocalesSupported);
    }

    @Test
    public void testGetandSetClaimsParameterSupported() throws Exception {
        String claimsParameterSupported = "parameter";
        oidProviderConfigResponse.setClaimsParameterSupported("parameter");
        String claimsParameterSupported1 = oidProviderConfigResponse.getClaimsParameterSupported();
        assertEquals(claimsParameterSupported1, claimsParameterSupported);
    }

    @Test
    public void testGetandSetRequestParameterSupported() throws Exception {
        String requestParameterSupported = "parameter";
        oidProviderConfigResponse.setRequestParameterSupported("parameter");
        String requestParameterSupported1 = oidProviderConfigResponse.getRequestParameterSupported();
        assertEquals(requestParameterSupported1, requestParameterSupported);
    }

    @Test
    public void testGetandSetRequestUriParameterSupported() throws Exception {
        String requestUriParameterSupported = "parameter";
        oidProviderConfigResponse.setRequestUriParameterSupported("parameter");
        String requestUriParameterSupported1 = oidProviderConfigResponse.getRequestUriParameterSupported();
        assertEquals(requestUriParameterSupported1, requestUriParameterSupported);
    }

    @Test
    public void testGetandSetRequireRequestUriRegistration() throws Exception {
        String requireRequestUriRegistration = "uri";
        oidProviderConfigResponse.setRequireRequestUriRegistration("uri");
        String requireRequestUriRegistration1 = oidProviderConfigResponse.getRequireRequestUriRegistration();
        assertEquals(requireRequestUriRegistration1, requireRequestUriRegistration);
    }

    @Test
    public void testGetandSetOpPolicyUri() throws Exception {
        String opPolicyUri = "uri";
        oidProviderConfigResponse.setOpPolicyUri("uri");
        String opPolicyUri1 = oidProviderConfigResponse.getOpPolicyUri();
        assertEquals(opPolicyUri1, opPolicyUri);
    }

    @Test
    public void testGetandSetOpTosUri() throws Exception {
        String opTosUri = "uri";
        oidProviderConfigResponse.setOpTosUri("uri");
        String opTosUri1 = oidProviderConfigResponse.getOpTosUri();
        assertEquals(opTosUri1, opTosUri);
    }

    @Test
    public void testGetConfigMap() throws Exception {
        Map map = oidProviderConfigResponse.getConfigMap();
        Assert.assertNotNull(map);
    }

}
