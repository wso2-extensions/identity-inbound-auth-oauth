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

package org.wso2.carbon.identity.oidc.dcr.factory;

import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.dcr.model.RegistrationResponse;
import org.wso2.carbon.identity.oidc.dcr.model.OIDCRegistrationResponse;
import org.wso2.carbon.identity.oidc.dcr.model.OIDCRegistrationResponseProfile;

import java.nio.file.Paths;
import java.util.Arrays;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNull;

/**
 * Test class for HttpOIDCRegistrationResponseFactory.
 */
public class HttpOIDCRegistrationResponseFactoryTest {

    private HttpOIDCRegistrationResponseFactory testedResponseFactory;

    @BeforeClass
    public void setUp() throws Exception {
        testedResponseFactory = new HttpOIDCRegistrationResponseFactory();
        String carbonHome = Paths.get(System.getProperty("user.dir"), "target", "test-classes").toString();
        System.setProperty(CarbonBaseConstants.CARBON_HOME, carbonHome);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain("carbon.super");
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername("admin");

    }

    @AfterMethod
    public void tearDown() throws Exception {
    }

    @Test
    public void testGetName() throws Exception {
        assertNull(testedResponseFactory.getName(), "Name should be null.");
    }

    @Test
    public void testCreate() throws Exception {
        OIDCRegistrationResponseProfile registrationResponseProfile = new OIDCRegistrationResponseProfile();
        registrationResponseProfile.setClientId("client_id");
        registrationResponseProfile.setClientName("client_name");
        registrationResponseProfile.setRedirectUrls(Arrays.asList("http://example.com", "http://foo.com"));
        registrationResponseProfile.setGrantTypes(Arrays.asList("code", "implicit"));
        registrationResponseProfile.setClientSecret("cl1ent_s3cr3t");
        registrationResponseProfile.setClientSecretExpiresAt("dummyExpiry");
        RegistrationResponse mockResponse = new RegistrationResponse.DCRRegisterResponseBuilder()
                .setRegistrationResponseProfile(registrationResponseProfile).build();
        HttpIdentityResponse identityResponse = testedResponseFactory.create(mockResponse).build();
        assertEquals(identityResponse.getStatusCode(), HttpServletResponse.SC_CREATED, "Invalid status code.");
        assertEquals(identityResponse.getHeaders().get(OAuthConstants.HTTP_RESP_HEADER_CACHE_CONTROL), OAuthConstants
                .HTTP_RESP_HEADER_VAL_CACHE_CONTROL_NO_STORE, "Invalid cache control header.");
        assertEquals(identityResponse.getHeaders().get(OAuthConstants.HTTP_RESP_HEADER_PRAGMA), OAuthConstants
                .HTTP_RESP_HEADER_VAL_PRAGMA_NO_CACHE, "Invalid pragma header.");
        assertEquals(identityResponse.getHeaders().get(HttpHeaders.CONTENT_TYPE), MediaType.APPLICATION_JSON,
                "Invalid content type header.");
    }

    @DataProvider(name = "CanHandleDataProvider")
    public Object[][] getCanHandleData() {
        return new Object[][]{
                {new IdentityResponse.IdentityResponseBuilder().build(), false},
                {new RegistrationResponse.DCRRegisterResponseBuilder().build(), true},
                {new OIDCRegistrationResponse.OIDCRegisterResponseBuilder().build(), true},
        };
    }

    @Test(dataProvider = "CanHandleDataProvider")
    public void testCanHandle(IdentityResponse response, boolean expected) throws Exception {
        assertEquals(testedResponseFactory.canHandle(response), expected, "Invalid canHandle response.");
    }

    @Test
    public void testGetPriority() throws Exception {
        assertEquals(testedResponseFactory.getPriority(), 50, "Priority should be 50.");
    }

    @Test
    public void testCanHandleException() throws Exception {
        assertFalse(testedResponseFactory.canHandle(new FrameworkException("DummyExceptionMsg")));
    }

}
