/*
 *  Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wso2.carbon.identity.oauth.scope.endpoint.impl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.scope.endpoint.ScopesApiService;
import org.wso2.carbon.identity.oauth.scope.endpoint.dto.ScopeDTO;
import org.wso2.carbon.identity.oauth.scope.endpoint.util.ScopeUtils;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ScopeClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ScopeException;
import org.wso2.carbon.identity.oauth2.Oauth2ScopeConstants;
import org.wso2.carbon.identity.oauth2.bean.Scope;

import javax.ws.rs.core.Response;
import java.util.Set;

/**
 * ScopesApiServiceImpl is used to handling scope bindings
 */
public class ScopesApiServiceImpl extends ScopesApiService {
    private static final Log LOG = LogFactory.getLog(ScopesApiServiceImpl.class);

    /**
     * Register a scope with the bindings
     *
     * @param scope details of the scope to be registered
     * @return Response with the status of the registration
     */
    @Override
    public Response registerScope(ScopeDTO scope) {
        Scope registeredScope = null;
        try {
            registeredScope = ScopeUtils.getOAuth2ScopeService().registerScope(ScopeUtils.getScope(scope));
        } catch (IdentityOAuth2ScopeClientException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Client Error while registering scope \n" + scope.toString(), e);
            }
            if (Oauth2ScopeConstants.ErrorMessages.ERROR_CODE_CONFLICT_REQUEST_EXISTING_SCOPE.getCode()
                    .equals(e.getErrorCode())) {
                ScopeUtils.handleScopeEndpointException(Response.Status.CONFLICT,
                        Response.Status.CONFLICT.getReasonPhrase(), e.getErrorCode(), e.getMessage(), LOG, e, false);
            } else {
                ScopeUtils.handleScopeEndpointException(Response.Status.BAD_REQUEST,
                        Response.Status.BAD_REQUEST.getReasonPhrase(), e.getErrorCode(), e.getMessage(), LOG, e, false);
            }
        } catch (IdentityOAuth2ScopeException e) {
            ScopeUtils.handleScopeEndpointException(Response.Status.INTERNAL_SERVER_ERROR,
                    Response.Status.INTERNAL_SERVER_ERROR.getReasonPhrase(), e.getErrorCode(), e.getMessage(), LOG, e,
                    true);
        } catch (Throwable throwable) {
            ScopeUtils.handleScopeEndpointException(Response.Status.INTERNAL_SERVER_ERROR,
                    Response.Status.INTERNAL_SERVER_ERROR.getReasonPhrase(), Oauth2ScopeConstants
                            .ErrorMessages.ERROR_CODE_UNEXPECTED.getCode(), throwable.getMessage(), LOG, throwable,
                    true);
        }
        return Response.status(Response.Status.CREATED).entity(registeredScope).build();
    }

    /**
     * Retrieve the scope of the given scope name
     *
     * @param name Name of the scope which need to get retrieved
     * @return Response with the retrieved scope/ retrieval status
     */
    @Override
    public Response getScope(String name) {
        Scope scope = null;

        try {
            scope = ScopeUtils.getOAuth2ScopeService().getScope(name);
        } catch (IdentityOAuth2ScopeClientException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Client Error while getting scope " + name, e);
            }
            if (Oauth2ScopeConstants.ErrorMessages.ERROR_CODE_NOT_FOUND_SCOPE.getCode()
                    .equals(e.getErrorCode())) {
                ScopeUtils.handleScopeEndpointException(Response.Status.NOT_FOUND,
                        Response.Status.NOT_FOUND.getReasonPhrase(), e.getErrorCode(), e.getMessage(), LOG, e, false);
            } else {
                ScopeUtils.handleScopeEndpointException(Response.Status.BAD_REQUEST,
                        Response.Status.BAD_REQUEST.getReasonPhrase(), e.getErrorCode(), e.getMessage(), LOG, e, false);
            }

        } catch (IdentityOAuth2ScopeException e) {
            ScopeUtils.handleScopeEndpointException(Response.Status.INTERNAL_SERVER_ERROR,
                    Response.Status.INTERNAL_SERVER_ERROR.getReasonPhrase(), e.getErrorCode(), e.getMessage(), LOG, e,
                    true);
        } catch (Throwable throwable) {
            ScopeUtils.handleScopeEndpointException(Response.Status.INTERNAL_SERVER_ERROR,
                    Response.Status.INTERNAL_SERVER_ERROR.getReasonPhrase(), Oauth2ScopeConstants
                            .ErrorMessages.ERROR_CODE_UNEXPECTED.getCode(), throwable.getMessage(), LOG, throwable,
                    true);
        }
        return Response.status(Response.Status.OK).entity(ScopeUtils.getScopeDTO(scope)).build();
    }

    /**
     * Retrieve the available scope list
     *
     * @param startIndex Start Index of the result set to enforce pagination
     * @param count      Number of elements in the result set to enforce pagination
     * @return Response with the retrieved scopes/ retrieval status
     */
    @Override
    public Response getScopes(Integer startIndex, Integer count) {
        Set<Scope> scopes = null;

        try {
            scopes = ScopeUtils.getOAuth2ScopeService().getScopes(startIndex, count);
        } catch (IdentityOAuth2ScopeException e) {
            ScopeUtils.handleScopeEndpointException(Response.Status.INTERNAL_SERVER_ERROR,
                    Response.Status.INTERNAL_SERVER_ERROR.getReasonPhrase(), e.getErrorCode(), e.getMessage(), LOG, e,
                    true);
        } catch (Throwable throwable) {
            ScopeUtils.handleScopeEndpointException(Response.Status.INTERNAL_SERVER_ERROR,
                    Response.Status.INTERNAL_SERVER_ERROR.getReasonPhrase(), Oauth2ScopeConstants
                            .ErrorMessages.ERROR_CODE_UNEXPECTED.getCode(), throwable.getMessage(), LOG, throwable,
                    true);
        }
        return Response.status(Response.Status.OK).entity(ScopeUtils.getScopeDTOs(scopes)).build();
    }

    /**
     * Check the existence of a scope
     *
     * @param name Name of the scope
     * @return Response with the indication whether the scope exists or not
     */
    @Override
    public Response isScopeExists(String name) {
        boolean isScopeExists = false;

        try {
            isScopeExists = ScopeUtils.getOAuth2ScopeService().isScopeExists(name);
        } catch (IdentityOAuth2ScopeClientException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Client Error while getting scope existence of scope name " + name, e);
            }
            ScopeUtils.handleScopeEndpointException(Response.Status.BAD_REQUEST,
                    Response.Status.BAD_REQUEST.getReasonPhrase(), e.getErrorCode(), e.getMessage(), LOG, e, false);

        } catch (IdentityOAuth2ScopeException e) {
            ScopeUtils.handleScopeEndpointException(Response.Status.INTERNAL_SERVER_ERROR,
                    Response.Status.INTERNAL_SERVER_ERROR.getReasonPhrase(), e.getErrorCode(), e.getMessage(), LOG, e,
                    true);
        } catch (Throwable throwable) {
            ScopeUtils.handleScopeEndpointException(Response.Status.INTERNAL_SERVER_ERROR,
                    Response.Status.INTERNAL_SERVER_ERROR.getReasonPhrase(), Oauth2ScopeConstants
                            .ErrorMessages.ERROR_CODE_UNEXPECTED.getCode(), throwable.getMessage(), LOG, throwable,
                    true);
        }

        if (isScopeExists) {
            return Response.status(Response.Status.OK).build();
        }
        return Response.status(Response.Status.NOT_FOUND).build();
    }

    /**
     * Update a scope
     *
     * @param scope details of the scope to be updated
     * @param name  name of the scope to be updated
     * @return
     */
    @Override
    public Response updateScope(ScopeDTO scope, String name) {
        ScopeDTO updatedScope = null;
        try {
            updatedScope = ScopeUtils.getScopeDTO(ScopeUtils.getOAuth2ScopeService()
                    .updateScope(ScopeUtils.getScope(scope), name));
        } catch (IdentityOAuth2ScopeClientException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Client Error while updating scope \n" + scope.toString(), e);
            }
            if (Oauth2ScopeConstants.ErrorMessages.ERROR_CODE_NOT_FOUND_SCOPE.getCode()
                    .equals(e.getErrorCode())) {
                ScopeUtils.handleScopeEndpointException(Response.Status.NOT_FOUND,
                        Response.Status.NOT_FOUND.getReasonPhrase(), e.getErrorCode(), e.getMessage(), LOG, e, false);
            } else {
                ScopeUtils.handleScopeEndpointException(Response.Status.BAD_REQUEST,
                        Response.Status.BAD_REQUEST.getReasonPhrase(), e.getErrorCode(), e.getMessage(), LOG, e, false);
            }
        } catch (IdentityOAuth2ScopeException e) {
            ScopeUtils.handleScopeEndpointException(Response.Status.INTERNAL_SERVER_ERROR,
                    Response.Status.INTERNAL_SERVER_ERROR.getReasonPhrase(), e.getErrorCode(), e.getMessage(), LOG, e,
                    true);
        } catch (Throwable throwable) {
            ScopeUtils.handleScopeEndpointException(Response.Status.INTERNAL_SERVER_ERROR,
                    Response.Status.INTERNAL_SERVER_ERROR.getReasonPhrase(), Oauth2ScopeConstants
                            .ErrorMessages.ERROR_CODE_UNEXPECTED.getCode(), throwable.getMessage(), LOG, throwable,
                    true);
        }
        return Response.status(Response.Status.OK).entity(updatedScope).build();
    }

    /**
     * Delete the scope for the given scope name
     *
     * @param name Name of the scope which need to get deleted
     * @return Response with the status of scope deletion
     */
    @Override
    public Response deleteScope(String name) {
        try {
            ScopeUtils.getOAuth2ScopeService().deleteScope(name);
        } catch (IdentityOAuth2ScopeClientException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Client Error while deleting scope " + name, e);
            }
            if (Oauth2ScopeConstants.ErrorMessages.ERROR_CODE_NOT_FOUND_SCOPE.getCode()
                    .equals(e.getErrorCode())) {
                ScopeUtils.handleScopeEndpointException(Response.Status.NOT_FOUND,
                        Response.Status.NOT_FOUND.getReasonPhrase(), e.getErrorCode(), e.getMessage(), LOG, e, false);
            } else {
                ScopeUtils.handleScopeEndpointException(Response.Status.BAD_REQUEST,
                        Response.Status.BAD_REQUEST.getReasonPhrase(), e.getErrorCode(), e.getMessage(), LOG, e, false);
            }
        } catch (IdentityOAuth2ScopeException e) {
            ScopeUtils.handleScopeEndpointException(Response.Status.INTERNAL_SERVER_ERROR,
                    Response.Status.INTERNAL_SERVER_ERROR.getReasonPhrase(), e.getErrorCode(), e.getMessage(), LOG, e,
                    true);
        } catch (Throwable throwable) {
            ScopeUtils.handleScopeEndpointException(Response.Status.INTERNAL_SERVER_ERROR,
                    Response.Status.INTERNAL_SERVER_ERROR.getReasonPhrase(), Oauth2ScopeConstants
                            .ErrorMessages.ERROR_CODE_UNEXPECTED.getCode(), throwable.getMessage(), LOG, throwable,
                    true);
        }
        return Response.status(Response.Status.OK).build();
    }
}