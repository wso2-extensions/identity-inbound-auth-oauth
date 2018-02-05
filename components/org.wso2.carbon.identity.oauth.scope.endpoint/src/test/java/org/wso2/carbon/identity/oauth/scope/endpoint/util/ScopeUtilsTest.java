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

package org.wso2.carbon.identity.oauth.scope.endpoint.util;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Assert;
import org.mockito.Mock;
import org.osgi.framework.BundleContext;
import org.osgi.util.tracker.ServiceTracker;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.IObjectFactory;
import org.testng.annotations.DataProvider;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth.scope.endpoint.Exceptions.ScopeEndpointException;
import org.wso2.carbon.identity.oauth.scope.endpoint.dto.ErrorDTO;
import org.wso2.carbon.identity.oauth.scope.endpoint.dto.ScopeDTO;
import org.wso2.carbon.identity.oauth.scope.endpoint.dto.ScopeToUpdateDTO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ScopeException;
import org.wso2.carbon.identity.oauth2.OAuth2ScopeService;
import org.wso2.carbon.identity.oauth2.bean.Scope;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import javax.ws.rs.core.Response;


import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

public class ScopeUtilsTest extends PowerMockTestCase {

    private final String CLIENT_NAME = "clientname";
    private final String CODE = "AJYRKLWB68NSB9";
    private final String MESSAGE = "Lifecycle exception occurred";
    private final String DESCRIPTION = "Error occurred while changing lifecycle state";
    private final String SCOPE_DESCRIPTION = "This is a sample scope";

    private static final Log log = LogFactory.getLog(ScopeUtilsTest.class);

    @Mock
    BundleContext bundleContext;

    @Mock
    ServiceTracker serviceTracker;

    @Mock
    private IdentityOAuth2ScopeException identityOAuth2ScopeException;

    @Mock
    OAuth2ScopeService service;

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }

    @Test(description = "Testing getErrorDTO")
    public void testGetErrorDTO() throws Exception {
        ErrorDTO errorDTOexpected = new ErrorDTO();
        errorDTOexpected.setCode(CODE);
        errorDTOexpected.setMessage(MESSAGE);
        errorDTOexpected.setDescription(DESCRIPTION);

        ErrorDTO errorDTO1 = ScopeUtils.getErrorDTO(MESSAGE, CODE, DESCRIPTION);
        assertEquals(errorDTO1.getCode(), errorDTOexpected.getCode(), "Actual code is not match for expected code");
        assertEquals(errorDTO1.getMessage(), errorDTOexpected.getMessage(), "Actual message is not match for expected message");
        assertEquals(errorDTO1.getDescription(), errorDTOexpected.getDescription(), "Actual description is not match for expected description");
    }

    @Test(description = "Testing getScope")
    public void testGetScope() throws Exception {

        ScopeDTO scopeDTO = new ScopeDTO();
        scopeDTO.setName(CLIENT_NAME);
        scopeDTO.setDisplayName(CLIENT_NAME);
        scopeDTO.setDescription(SCOPE_DESCRIPTION);
        ArrayList binding = new ArrayList();

        Scope scope1 = ScopeUtils.getScope(scopeDTO);
        assertEquals(scope1.getName(), CLIENT_NAME, "Actual name is not match for expected name");
        assertEquals(scope1.getDisplayName(), CLIENT_NAME, "Actual display name is not match for expected display name");
        assertEquals(scope1.getDescription(), SCOPE_DESCRIPTION, "Actual description is not match for expected description");
        assertEquals(scope1.getBindings(), binding, "Actual binding is not match for expected binding");
    }

    @Test(description = "Testing getScopeDTO")
    public void testGetScopeDTO() throws Exception {
        ArrayList bindings = new ArrayList();
        bindings.add("binding1");
        Scope scope = new Scope(CLIENT_NAME, CLIENT_NAME, SCOPE_DESCRIPTION, bindings);

        ScopeDTO scopeDTO1 = ScopeUtils.getScopeDTO(scope);
        assertEquals(scopeDTO1.getBindings(), bindings, "Actual binding is not match for expected binding");
        assertTrue(scopeDTO1.getBindings().get(0).contains("binding1"));
        assertEquals(scopeDTO1.getDisplayName(), CLIENT_NAME, "Actual display name is not match for expected display name");
        assertEquals(scopeDTO1.getDescription(), SCOPE_DESCRIPTION, "Actual description is not match for expected description");
        assertEquals(scopeDTO1.getName(), CLIENT_NAME, "Actual name is not match for expected name");
    }

    @Test(description = "Testing getUpdateScope")
    public void testGetUpdatedScope() throws Exception {

        ScopeToUpdateDTO sc = new ScopeToUpdateDTO();
        ArrayList bindings = new ArrayList();
        sc.setDisplayName(CLIENT_NAME);
        sc.setDescription(SCOPE_DESCRIPTION);

        Scope scope1 = ScopeUtils.getUpdatedScope(sc, "Actual name is not match for expected name");
        assertEquals(scope1.getBindings(), bindings, "Actual binding is not match for expected binding");
        assertEquals(scope1.getDescription(), SCOPE_DESCRIPTION, "Actual description is not match for expected description");
    }

    @Test(description = "Testing getScopeDTO")
    public void testGetScopeDTOs() throws Exception {
        int scopeName;
        int scopeSize = 15;
        Set<Scope> scopes = new HashSet<>();
        ArrayList<String> bindings = new ArrayList<>(Arrays.asList("scope1", "scope2"));
        for (int i = 0; i < scopeSize; i++) {
            Scope scope1 = new Scope(CLIENT_NAME + "" + i, CLIENT_NAME + "" + i, SCOPE_DESCRIPTION, bindings);
            scopes.add(scope1);
        }
        Set<ScopeDTO> scopeDTOs = ScopeUtils.getScopeDTOs(scopes);
        assertNotNull(scopeDTOs);
        assertEquals(scopeDTOs.size(), scopeSize, "Invalid Scopes size");
    }

    @DataProvider(name = "BuildScopeEndpointException")
    public Object[][] buildScopeEndpointException() {
        Response.Status status = Response.Status.BAD_REQUEST;
        Throwable throwable1 = new ScopeEndpointException(status);
        Throwable throwable2 = new RuntimeException("BAD_REQUEST_INVALID_REDIRECT_URI");
        return new Object[][]{
                {status, throwable1, true},
                {status, throwable1, false},
                {status, throwable2, true},
                {status, throwable2, false},
                {status, throwable1, true}
        };
    }

    @Test(dataProvider = "BuildScopeEndpointException")
    public void testHandleErrorResponse(Response.Status status, Throwable throwable, boolean isServerException) throws Exception {
        String message = "Scope";
        // To check whether exception generated correctly.
        try {
            ScopeUtils.handleErrorResponse(status, message, throwable, isServerException, log);
            Assert.fail();
        } catch (ScopeEndpointException e) {
            assertEquals(e.getResponse().getStatus(), status.getStatusCode());
        }
    }
}

