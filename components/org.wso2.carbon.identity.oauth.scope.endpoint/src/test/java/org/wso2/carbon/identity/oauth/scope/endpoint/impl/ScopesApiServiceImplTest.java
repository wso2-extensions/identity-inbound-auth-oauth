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
package org.wso2.carbon.identity.oauth.scope.endpoint.impl;

import org.apache.commons.logging.Log;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth.scope.endpoint.Exceptions.ScopeEndpointException;
import org.wso2.carbon.identity.oauth.scope.endpoint.dto.ErrorDTO;
import org.wso2.carbon.identity.oauth.scope.endpoint.dto.ScopeDTO;
import org.wso2.carbon.identity.oauth.scope.endpoint.dto.ScopeToUpdateDTO;
import org.wso2.carbon.identity.oauth.scope.endpoint.util.ScopeUtils;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ScopeClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ScopeException;
import org.wso2.carbon.identity.oauth2.OAuth2ScopeService;
import org.wso2.carbon.identity.oauth2.Oauth2ScopeConstants;
import org.wso2.carbon.identity.oauth2.bean.Scope;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;

import javax.ws.rs.core.Response;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.reset;
import static org.powermock.api.mockito.PowerMockito.doNothing;
import static org.powermock.api.mockito.PowerMockito.doThrow;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;

@PowerMockIgnore("javax.*")
@PrepareForTest({ScopeUtils.class,OAuth2ScopeService.class})
public class ScopesApiServiceImplTest extends PowerMockIdentityBaseTest {

    private ScopesApiServiceImpl scopesApiService = new ScopesApiServiceImpl();
    private String someScopeName;
    private String someScopeDescription;

    @Mock
    private OAuth2ScopeService oAuth2ScopeService;

    @BeforeMethod
    public void setUp() throws Exception {
        someScopeName = "scope";
        someScopeDescription = "some description";
        mockStatic(ScopeUtils.class);
        when(ScopeUtils.getOAuth2ScopeService()).thenReturn(oAuth2ScopeService);
    }

    @DataProvider(name = "BuildUpdateScope")
    public Object[][] buildUpdateApplication() {

        IdentityOAuth2ScopeClientException identityOAuth2ScopeClientException =
                new IdentityOAuth2ScopeClientException("Oauth2 Scope Client Exception");
        IdentityOAuth2ScopeException identityOAuth2ScopeException = new IdentityOAuth2ScopeException("Oauth2 Scope " +
                "Exception");
        return new Object[][]{
                {Response.Status.OK, null},
                {Response.Status.BAD_REQUEST, identityOAuth2ScopeClientException},
                {Response.Status.NOT_FOUND, identityOAuth2ScopeClientException},
                {Response.Status.INTERNAL_SERVER_ERROR, identityOAuth2ScopeException}
        };
    }

    @Test(dataProvider = "BuildUpdateScope")
    public void testUpdateScope(Response.Status expectation, Throwable throwable) throws Exception {

        ScopeToUpdateDTO scopeToUpdateDTO = new ScopeToUpdateDTO();
        scopeToUpdateDTO.setDescription("some description");
        scopeToUpdateDTO.setBindings(Collections.<String>emptyList());

        if (Response.Status.OK.equals(expectation)) {
            when(ScopeUtils.getScopeDTO(any(Scope.class))).thenReturn(any(ScopeDTO.class));
            assertEquals(scopesApiService.updateScope(scopeToUpdateDTO, someScopeName).getStatus(),
                    Response.Status.OK.getStatusCode(), "Error occurred while updating scopes");
        } else if (Response.Status.BAD_REQUEST.equals(expectation)) {
            when(oAuth2ScopeService.updateScope(any(Scope.class))).thenThrow(IdentityOAuth2ScopeClientException.class);
            callRealMethod();
            try {
                scopesApiService.updateScope(scopeToUpdateDTO, someScopeName);
            } catch (ScopeEndpointException e) {
                assertEquals(e.getResponse().getStatus(), Response.Status.BAD_REQUEST.getStatusCode(),
                        "Cannot find HTTP Response, Bad Request in Case of " +
                                "IdentityOAuth2ScopeClientException");
                assertEquals(((ErrorDTO) (e.getResponse().getEntity())).getMessage(),
                        Response.Status.BAD_REQUEST.getReasonPhrase(), "Cannot find appropriate error message " +
                                "for HTTP Response, Bad Request");
            } finally {
                reset(oAuth2ScopeService);
            }
        } else if (Response.Status.NOT_FOUND.equals(expectation)) {
            ((IdentityOAuth2ScopeException) throwable).setErrorCode(Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_NOT_FOUND_SCOPE.getCode());
            when(oAuth2ScopeService.updateScope(any(Scope.class))).thenThrow(throwable);
            callRealMethod();
            try {
                scopesApiService.updateScope(scopeToUpdateDTO, someScopeName);
            } catch (ScopeEndpointException e) {
                assertEquals(e.getResponse().getStatus(), Response.Status.NOT_FOUND.getStatusCode(),
                        "Cannot find HTTP Response, Not Found in Case of " +
                                "IdentityOAuth2ScopeClientException");
                assertEquals(((ErrorDTO) (e.getResponse().getEntity())).getMessage(),
                        Response.Status.NOT_FOUND.getReasonPhrase(), "Cannot find appropriate error message " +
                                "for HTTP Response, Not Found");
            } finally {
                reset(oAuth2ScopeService);
            }
        } else if (Response.Status.INTERNAL_SERVER_ERROR.equals(expectation)) {
            when(oAuth2ScopeService.updateScope(any(Scope.class))).thenThrow(IdentityOAuth2ScopeException.class);
            callRealMethod();
            try {
                scopesApiService.updateScope(scopeToUpdateDTO, someScopeName);
            } catch (ScopeEndpointException e) {
                assertEquals(e.getResponse().getStatus(), Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(),
                        "Cannot find HTTP Response, Internal Server Error in case of " +
                                "IdentityOAuth2ScopeException");
                assertNull(e.getResponse().getEntity(), "Do not include error message in case of " +
                        "Server Exception");
            } finally {
                reset(oAuth2ScopeService);
            }
        }
    }

    @DataProvider(name = "BuildGetScope")
    public Object[][] buildGetApplication() {
        IdentityOAuth2ScopeClientException identityOAuth2ScopeClientException = new IdentityOAuth2ScopeClientException
                ("Oauth2 Scope Client Exception");
        IdentityOAuth2ScopeException identityOAuth2ScopeException = new IdentityOAuth2ScopeException
                ("Oauth2 Scope Exception");
        return new Object[][]{
                {Response.Status.OK, null},
                {Response.Status.BAD_REQUEST, identityOAuth2ScopeClientException},
                {Response.Status.NOT_FOUND, identityOAuth2ScopeClientException},
                {Response.Status.INTERNAL_SERVER_ERROR, identityOAuth2ScopeException}
        };
    }

    @Test(dataProvider = "BuildGetScope")
    public void testGetScope(Response.Status expectation, Throwable throwable) throws Exception {

        if (Response.Status.OK.equals(expectation)) {
            when(oAuth2ScopeService.getScope(someScopeName)).thenReturn(any(Scope.class));
            assertEquals(scopesApiService.getScope(someScopeName).getStatus(), Response.Status.OK.getStatusCode(),
                    "Error occurred while getting a scope");
        } else if (Response.Status.BAD_REQUEST.equals(expectation)) {
            when(oAuth2ScopeService.getScope(someScopeName)).thenThrow(throwable);
            callRealMethod();
            try {
                scopesApiService.getScope(someScopeName);
            } catch (ScopeEndpointException e) {
                assertEquals(e.getResponse().getStatus(), Response.Status.BAD_REQUEST.getStatusCode(),
                        "Cannot find HTTP Response, Bad Request in Case of " +
                                "IdentityOAuth2ScopeClientException");
                assertEquals(((ErrorDTO) (e.getResponse().getEntity())).getMessage(),
                        Response.Status.BAD_REQUEST.getReasonPhrase(), "Cannot find appropriate error message " +
                                "for HTTP Response, Bad Request");
            } finally {
                reset(oAuth2ScopeService);
            }
        } else if (Response.Status.NOT_FOUND.equals(expectation)) {
            ((IdentityOAuth2ScopeException) throwable).setErrorCode(Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_NOT_FOUND_SCOPE.getCode());
            when(oAuth2ScopeService.getScope(someScopeName)).thenThrow(throwable);
            callRealMethod();
            try {
                scopesApiService.getScope(someScopeName);
            } catch (ScopeEndpointException e) {
                assertEquals(e.getResponse().getStatus(), Response.Status.NOT_FOUND.getStatusCode(),
                        "Cannot find HTTP Response, Not Found in Case of " +
                                "IdentityOAuth2ScopeClientException");
                assertEquals(((ErrorDTO) (e.getResponse().getEntity())).getMessage(),
                        Response.Status.NOT_FOUND.getReasonPhrase(), "Cannot find appropriate error message " +
                                "for HTTP Response, Not Found");
            } finally {
                reset(oAuth2ScopeService);
            }
        } else if (Response.Status.INTERNAL_SERVER_ERROR.equals(expectation)) {
            when(oAuth2ScopeService.getScope(someScopeName)).thenThrow(IdentityOAuth2ScopeException.class);
            ;
            callRealMethod();
            try {
                scopesApiService.getScope(someScopeName);
            } catch (ScopeEndpointException e) {
                assertEquals(e.getResponse().getStatus(), Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(),
                        "Cannot find HTTP Response, Internal Server Error in case of " +
                                "IdentityOAuth2ScopeException");
                assertNull(e.getResponse().getEntity(), "Do not include error message in case of " +
                        "Server Exception");
            } finally {
                reset(oAuth2ScopeService);
            }
        }
    }

    @DataProvider(name = "BuildgetScopes")
    public Object[][] getscopes() {
        return new Object[][]{
                {Response.Status.OK}, {Response.Status.INTERNAL_SERVER_ERROR}
        };
    }

    @Test(dataProvider = "BuildgetScopes")
    public void testGetScopes(Response.Status expectation) throws Exception {

        Set<Scope> scopes = new HashSet<>();
        scopes.add(new Scope(someScopeName, someScopeName, someScopeDescription));
        int startIndex = 0;
        int count = 1;

        if (Response.Status.OK.equals(expectation)) {
            when(oAuth2ScopeService.getScopes(any(Integer.class), any(Integer.class))).thenReturn(scopes);
            when(ScopeUtils.class, "getScopeDTOs", any(Set.class)).thenCallRealMethod();
            Response response = scopesApiService.getScopes(startIndex, count);
            assertEquals(response.getStatus(), Response.Status.OK.getStatusCode(),
                    "Error occurred while getting scopes");
            assertEquals(((HashSet) response.getEntity()).size(), count, "Cannot Retrieve Expected Scopes");
        } else if (Response.Status.INTERNAL_SERVER_ERROR.equals(expectation)) {
            when(oAuth2ScopeService.getScopes(any(Integer.class), any(Integer.class))).
                    thenThrow(IdentityOAuth2ScopeException.class);
            callRealMethod();
            try {
                scopesApiService.getScopes(startIndex, count);
            } catch (ScopeEndpointException e) {
                assertEquals(e.getResponse().getStatus(), Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(),
                        "Cannot find HTTP Response, Internal Server Error in case of " +
                                "IdentityOAuth2ScopeException");
                assertNull(e.getResponse().getEntity(), "Do not include error message in case of " +
                        "Server Exception");
            }
        }
    }

    @DataProvider(name = "BuildDeleteScope")
    public Object[][] buildDeleteApplication() {
        IdentityOAuth2ScopeClientException identityOAuth2ScopeClientException = new IdentityOAuth2ScopeClientException
                ("Oauth2 Scope Client Exception");
        IdentityOAuth2ScopeException identityOAuth2ScopeException = new IdentityOAuth2ScopeException
                ("Oauth2 Scope Exception");
        return new Object[][]{
                {Response.Status.OK, null},
                {Response.Status.BAD_REQUEST, identityOAuth2ScopeClientException},
                {Response.Status.NOT_FOUND, identityOAuth2ScopeClientException}
        };
    }

    @Test(dataProvider = "BuildDeleteScope")
    public void testDeleteScope(Response.Status expectation, Throwable throwable) throws Exception {


        if (Response.Status.OK.equals(expectation)) {
            doNothing().when(oAuth2ScopeService).deleteScope(any(String.class));
            assertEquals(scopesApiService.deleteScope(any(String.class)).getStatus(), Response.Status.OK.getStatusCode());
        } else if (Response.Status.BAD_REQUEST.equals(expectation)) {
            doThrow(throwable).when(oAuth2ScopeService).deleteScope(any(String.class));
            callRealMethod();
            try {
                scopesApiService.deleteScope(someScopeName);
            } catch (ScopeEndpointException e) {
                assertEquals(e.getResponse().getStatus(), Response.Status.BAD_REQUEST.getStatusCode(),
                        "Cannot find HTTP Response, Bad Request in Case of " +
                                "IdentityOAuth2ScopeClientException");
                assertEquals(((ErrorDTO) (e.getResponse().getEntity())).getMessage(),
                        Response.Status.BAD_REQUEST.getReasonPhrase(), "Cannot find appropriate error message " +
                                "for HTTP Response, Bad Request");
            } finally {
                reset(oAuth2ScopeService);
            }
        } else if (Response.Status.NOT_FOUND.equals(expectation)) {
            ((IdentityOAuth2ScopeException) throwable).setErrorCode(Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_NOT_FOUND_SCOPE.getCode());
            doThrow(throwable).when(oAuth2ScopeService).deleteScope(any(String.class));
            callRealMethod();
            try {
                scopesApiService.deleteScope(someScopeName);
            } catch (ScopeEndpointException e) {
                assertEquals(e.getResponse().getStatus(), Response.Status.NOT_FOUND.getStatusCode(),
                        "Cannot find HTTP Response, Not Found in Case of " +
                                "IdentityOAuth2ScopeClientException");
                assertEquals(((ErrorDTO) (e.getResponse().getEntity())).getMessage(),
                        Response.Status.NOT_FOUND.getReasonPhrase(), "Cannot find appropriate error message " +
                                "for HTTP Response, Not Found");
            } finally {
                reset(oAuth2ScopeService);
            }
        }
    }

    @DataProvider(name = "BuildRegisterScope")
    public Object[][] buildRegisterApplication() {
        IdentityOAuth2ScopeClientException identityOAuth2ScopeClientException = new IdentityOAuth2ScopeClientException
                ("Oauth2 Scope Client Exception");
        IdentityOAuth2ScopeException identityOAuth2ScopeException = new IdentityOAuth2ScopeException
                ("Oauth2 Scope Exception");
        return new Object[][]{
                {Response.Status.OK, null},
                {Response.Status.BAD_REQUEST, identityOAuth2ScopeClientException},
                {Response.Status.CONFLICT, identityOAuth2ScopeClientException},
                {Response.Status.INTERNAL_SERVER_ERROR, identityOAuth2ScopeException}
        };
    }

    @Test(dataProvider = "BuildRegisterScope")
    public void testRegisterScope(Response.Status expectation, Throwable throwable) throws Exception {

        ScopeDTO scopeDTO = new ScopeDTO();
        scopeDTO.setDescription("some description");
        scopeDTO.setBindings(Collections.<String>emptyList());
        if (Response.Status.OK.equals(expectation)) {
            when(oAuth2ScopeService.registerScope(any(Scope.class))).thenReturn(any(Scope.class));
            assertEquals(scopesApiService.registerScope(scopeDTO).getStatus(), Response.Status.CREATED.getStatusCode(),
                    "Error occurred while registering scopes");
        } else if (Response.Status.BAD_REQUEST.equals(expectation)) {
            when(oAuth2ScopeService.registerScope(any(Scope.class))).thenThrow(throwable);
            callRealMethod();
            try {
                scopesApiService.registerScope(scopeDTO);
            } catch (ScopeEndpointException e) {
                assertEquals(e.getResponse().getStatus(), Response.Status.BAD_REQUEST.getStatusCode(),
                        "Cannot find HTTP Response, Bad Request in Case of " +
                                "IdentityOAuth2ScopeClientException");
                assertEquals(((ErrorDTO) (e.getResponse().getEntity())).getMessage(),
                        Response.Status.BAD_REQUEST.getReasonPhrase(), "Cannot find appropriate error message " +
                                "for HTTP Response, Bad Request");
            } finally {
                reset(oAuth2ScopeService);
            }
        } else if (Response.Status.CONFLICT.equals(expectation)) {
            ((IdentityOAuth2ScopeException) throwable).setErrorCode(Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_CONFLICT_REQUEST_EXISTING_SCOPE.getCode());
            when(oAuth2ScopeService.registerScope(any(Scope.class))).thenThrow(throwable);
            callRealMethod();
            try {
                scopesApiService.registerScope(scopeDTO);
            } catch (ScopeEndpointException e) {
                assertEquals(e.getResponse().getStatus(), Response.Status.CONFLICT.getStatusCode(),
                        "Cannot find HTTP Response, Conflict in Case of " +
                                "IdentityOAuth2ScopeClientException");
                assertEquals(((ErrorDTO) (e.getResponse().getEntity())).getMessage(),
                        Response.Status.CONFLICT.getReasonPhrase(), "Cannot find appropriate error message " +
                                "for HTTP Response, Conflict");
            } finally {
                reset(oAuth2ScopeService);
            }
        } else if (Response.Status.INTERNAL_SERVER_ERROR.equals(expectation)) {
            when(oAuth2ScopeService.registerScope(any(Scope.class))).thenThrow(IdentityOAuth2ScopeException.class);
            callRealMethod();
            try {
                scopesApiService.registerScope(scopeDTO);
            } catch (ScopeEndpointException e) {
                assertEquals(e.getResponse().getStatus(), Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(),
                        "Cannot find HTTP Response, Internal Server Error in case of " +
                                "IdentityOAuth2ScopeException");
                assertNull(e.getResponse().getEntity(), "Do not include error message in case of " +
                        "Server Exception");
            } finally {
                reset(oAuth2ScopeService);
            }
        }
    }

    @DataProvider(name = "checkisScopeException")
    public Object[][] checkScopeException() {

        IdentityOAuth2ScopeClientException identityOAuth2ScopeClientException = new IdentityOAuth2ScopeClientException
                ("Oauth2 Scope Client Exception");
        IdentityOAuth2ScopeException identityOAuth2ScopeException = new IdentityOAuth2ScopeException
                ("Oauth2 Scope Exception");
        return new Object[][]{
                {Response.Status.OK, null},
                {Response.Status.NOT_FOUND, null},
                {Response.Status.BAD_REQUEST, identityOAuth2ScopeClientException},
                {Response.Status.INTERNAL_SERVER_ERROR, identityOAuth2ScopeException}
        };
    }

    @Test(dataProvider = "checkisScopeException")
    public void testIsScopeExists(Response.Status expectation, Throwable throwable) throws Exception {

        if (Response.Status.OK.equals(expectation)) {
            when(oAuth2ScopeService.isScopeExists(someScopeName)).thenReturn(Boolean.TRUE);
            assertEquals(scopesApiService.isScopeExists(someScopeName).getStatus(), Response.Status.OK.getStatusCode(),
                    "Error occurred while checking is scope exist");
        } else if (Response.Status.NOT_FOUND.equals(expectation)) {
            when(oAuth2ScopeService.isScopeExists(someScopeName)).thenReturn(Boolean.FALSE);
            assertEquals(scopesApiService.isScopeExists(someScopeName).getStatus(),
                    Response.Status.NOT_FOUND.getStatusCode(),
                    "Given scope does not exist but error while checking isExist");
        } else if (Response.Status.BAD_REQUEST.equals(expectation)) {
            when(oAuth2ScopeService.isScopeExists(someScopeName)).thenThrow(throwable);
            callRealMethod();
            try {
                scopesApiService.isScopeExists(someScopeName);
            } catch (ScopeEndpointException e) {
                assertEquals(e.getResponse().getStatus(), Response.Status.BAD_REQUEST.getStatusCode(),
                        "Cannot find HTTP Response, Bad Request in Case of " +
                                "IdentityOAuth2ScopeClientException");
                assertEquals(((ErrorDTO) (e.getResponse().getEntity())).getMessage(),
                        Response.Status.BAD_REQUEST.getReasonPhrase(), "Cannot find appropriate error message " +
                                "for HTTP Response, Bad Request");
            } finally {
                reset(oAuth2ScopeService);
            }
        } else if (Response.Status.INTERNAL_SERVER_ERROR.equals(expectation)) {
            when(oAuth2ScopeService.isScopeExists("scope")).thenThrow(IdentityOAuth2ScopeException.class);
            callRealMethod();
            try {
                scopesApiService.isScopeExists(someScopeName);
            } catch (ScopeEndpointException e) {
                assertEquals(e.getResponse().getStatus(), Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(),
                        "Cannot find HTTP Response, Internal Server Error in case of " +
                                "IdentityOAuth2ScopeException");
                assertNull(e.getResponse().getEntity(), "Do not include error message in case of " +
                        "Server Exception");
            } finally {
                reset(oAuth2ScopeService);
            }
        }
    }

    private void callRealMethod() throws Exception {
        when(ScopeUtils.class, "handleErrorResponse", any(Response.Status.class), any(String.class),
                any(Throwable.class), any(boolean.class), any(Log.class)).thenCallRealMethod();
        when(ScopeUtils.class, "buildScopeEndpointException", any(Response.Status.class),
                any(String.class), any(String.class), any(String.class), any(boolean.class)).thenCallRealMethod();
        when(ScopeUtils.class, "getErrorDTO", any(String.class), any(String.class),
                any(String.class)).thenCallRealMethod();
    }

}

