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
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.scope.endpoint.ScopesApiService;
import org.wso2.carbon.identity.oauth.scope.endpoint.dto.ScopeDTO;
import org.wso2.carbon.identity.oauth.scope.endpoint.dto.ScopeToUpdateDTO;
import org.wso2.carbon.identity.oauth.scope.endpoint.util.ScopeUtils;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ScopeClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ScopeException;
import org.wso2.carbon.identity.oauth2.Oauth2ScopeConstants;
import org.wso2.carbon.identity.oauth2.bean.Scope;
import org.wso2.carbon.user.api.AuthorizationManager;
import org.wso2.carbon.user.api.UserStoreException;

import java.net.URI;
import java.util.Set;

import javax.ws.rs.core.Response;

import static org.wso2.carbon.identity.oauth.common.OAuthConstants.TENANT_NAME_FROM_CONTEXT;
import static org.wso2.carbon.identity.oauth.scope.endpoint.Constants.SERVER_API_PATH_COMPONENT;
import static org.wso2.carbon.identity.oauth.scope.endpoint.Constants.TENANT_CONTEXT_PATH_COMPONENT;

/**
 * ScopesApiServiceImpl is used to handling scope bindings.
 */
public class ScopesApiServiceImpl extends ScopesApiService {

    private static final Log LOG = LogFactory.getLog(ScopesApiServiceImpl.class);
    private static final String INTERNAL_SCOPE_PREFIX = "internal_";
    /**
     * Register a scope with the bindings.
     *
     * @param scope details of the scope to be registered
     * @return Response with the status of the registration.
     */
    @Override
    public Response registerScope(ScopeDTO scope) {

        Scope registeredScope = null;
        try {
            validateAddRequest(scope);
            registeredScope = ScopeUtils.getOAuth2ScopeService().registerScope(ScopeUtils.getScope(scope));
        } catch (IdentityOAuth2ScopeClientException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Client Error while registering scope \n" + scope.toString(), e);
            }
            if (Oauth2ScopeConstants.ErrorMessages.ERROR_CODE_CONFLICT_REQUEST_EXISTING_SCOPE.getCode()
                    .equals(e.getErrorCode())) {
                ScopeUtils.handleErrorResponse(Response.Status.CONFLICT,
                        Response.Status.CONFLICT.getReasonPhrase(), e, false, LOG);
            } else if (Oauth2ScopeConstants.ErrorMessages.ERROR_CODE_NOT_AUTHORIZED_ADD_INTERNAL_SCOPE.getCode()
                    .equals(e.getErrorCode())) {
                ScopeUtils.handleErrorResponse(Response.Status.FORBIDDEN,
                        Response.Status.FORBIDDEN.getReasonPhrase(), e, false, LOG);
            } else {
                ScopeUtils.handleErrorResponse(Response.Status.BAD_REQUEST,
                        Response.Status.BAD_REQUEST.getReasonPhrase(), e, false, LOG);
            }
        } catch (IdentityOAuth2ScopeException e) {
            ScopeUtils.handleErrorResponse(Response.Status.INTERNAL_SERVER_ERROR,
                    Response.Status.INTERNAL_SERVER_ERROR.getReasonPhrase(), e, true, LOG);
        } catch (Throwable throwable) {
            ScopeUtils.handleErrorResponse(Response.Status.INTERNAL_SERVER_ERROR,
                    Response.Status.INTERNAL_SERVER_ERROR.getReasonPhrase(), throwable, true, LOG);
        }
        return Response.status(Response.Status.CREATED).location(buildURIForHeader(scope.getName())).
                entity(registeredScope).build();
    }

    /**
     * Retrieve the scope of the given scope name.
     *
     * @param name Name of the scope which need to get retrieved
     * @return Response with the retrieved scope/ retrieval status.
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
            if (Oauth2ScopeConstants.ErrorMessages.ERROR_CODE_NOT_FOUND_SCOPE.getCode().equals(e.getErrorCode())) {
                ScopeUtils.handleErrorResponse(Response.Status.NOT_FOUND,
                        Response.Status.NOT_FOUND.getReasonPhrase(), e, false, LOG);
            } else {
                ScopeUtils.handleErrorResponse(Response.Status.BAD_REQUEST,
                        Response.Status.BAD_REQUEST.getReasonPhrase(), e, false, LOG);
            }

        } catch (IdentityOAuth2ScopeException e) {
            ScopeUtils.handleErrorResponse(Response.Status.INTERNAL_SERVER_ERROR,
                    Response.Status.INTERNAL_SERVER_ERROR.getReasonPhrase(), e, true, LOG);
        } catch (Throwable throwable) {
            ScopeUtils.handleErrorResponse(Response.Status.INTERNAL_SERVER_ERROR,
                    Response.Status.INTERNAL_SERVER_ERROR.getReasonPhrase(), throwable, true, LOG);
        }
        return Response.status(Response.Status.OK).entity(ScopeUtils.getScopeDTO(scope)).build();
    }

    /**
     * Retrieve the available scope list.
     *
     * @param startIndex        Start Index of the result set to enforce pagination.
     * @param count             Number of elements in the result set to enforce pagination.
     * @param includeOIDCScopes Include OIDC scopes as well.
     * @param requestedScopes   Requested set of scopes to be return in the response.
     * @return Response with the retrieved scopes retrieval status.
     */
    @Override
    public Response getScopes(Integer startIndex, Integer count, Boolean includeOIDCScopes, String requestedScopes) {

        Set<Scope> scopes = null;

        try {
            scopes =
                    ScopeUtils.getOAuth2ScopeService().getScopes(startIndex, count, includeOIDCScopes, requestedScopes);
        } catch (IdentityOAuth2ScopeException e) {
            ScopeUtils.handleErrorResponse(Response.Status.INTERNAL_SERVER_ERROR,
                    Response.Status.INTERNAL_SERVER_ERROR.getReasonPhrase(), e, true, LOG);
        } catch (Throwable throwable) {
            ScopeUtils.handleErrorResponse(Response.Status.INTERNAL_SERVER_ERROR,
                    Response.Status.INTERNAL_SERVER_ERROR.getReasonPhrase(), throwable, true, LOG);
        }
        return Response.status(Response.Status.OK).entity(ScopeUtils.getScopeDTOs(scopes)).build();
    }

    /**
     * Retrieve the available scope list.
     *
     * @param startIndex Start Index of the result set to enforce pagination.
     * @param count      Number of elements in the result set to enforce pagination.
     * @return Response with the retrieved scopes/ retrieval status.
     * @deprecated use {@link #getScopes(Integer, Integer, Boolean, String)} instead.
     */
    public Response getScopes(Integer startIndex, Integer count) {

        return getScopes(startIndex, count, false, null);
    }

    /**
     * Check the existence of a scope.
     *
     * @param name Name of the scope
     * @return Response with the indication whether the scope exists or not.
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
            ScopeUtils.handleErrorResponse(Response.Status.BAD_REQUEST,
                    Response.Status.BAD_REQUEST.getReasonPhrase(), e, false, LOG);

        } catch (IdentityOAuth2ScopeException e) {
            ScopeUtils.handleErrorResponse(Response.Status.INTERNAL_SERVER_ERROR,
                    Response.Status.INTERNAL_SERVER_ERROR.getReasonPhrase(), e, true, LOG);
        } catch (Throwable throwable) {
            ScopeUtils.handleErrorResponse(Response.Status.INTERNAL_SERVER_ERROR,
                    Response.Status.INTERNAL_SERVER_ERROR.getReasonPhrase(), throwable, true, LOG);
        }

        if (isScopeExists) {
            return Response.status(Response.Status.OK).build();
        }
        return Response.status(Response.Status.NOT_FOUND).entity(ScopeUtils.getCorrelation()).build();
    }

    /**
     * Update a scope
     *
     * @param scope details of the scope to be updated.
     * @param name  name of the scope to be updated.
     * @return
     */
    @Override
    public Response updateScope(ScopeToUpdateDTO scope, String name) {

        ScopeDTO updatedScope = null;
        try {
            validateUpdateRequest(name);
            updatedScope = ScopeUtils.getScopeDTO(ScopeUtils.getOAuth2ScopeService()
                    .updateScope(ScopeUtils.getUpdatedScope(scope, name)));
        } catch (IdentityOAuth2ScopeClientException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Client Error while updating scope \n" + scope.toString(), e);
            }
            if (Oauth2ScopeConstants.ErrorMessages.ERROR_CODE_NOT_FOUND_SCOPE.getCode()
                    .equals(e.getErrorCode())) {
                ScopeUtils.handleErrorResponse(Response.Status.NOT_FOUND,
                        Response.Status.NOT_FOUND.getReasonPhrase(), e, false, LOG);
            } else if (Oauth2ScopeConstants.ErrorMessages.ERROR_CODE_NOT_AUTHORIZED_UPDATE_INTERNAL_SCOPE.getCode()
                    .equals(e.getErrorCode())) {
                ScopeUtils.handleErrorResponse(Response.Status.FORBIDDEN,
                        Response.Status.FORBIDDEN.getReasonPhrase(), e, false, LOG);
            } else {
                ScopeUtils.handleErrorResponse(Response.Status.BAD_REQUEST,
                        Response.Status.BAD_REQUEST.getReasonPhrase(), e, false, LOG);
            }
        } catch (IdentityOAuth2ScopeException e) {
            ScopeUtils.handleErrorResponse(Response.Status.INTERNAL_SERVER_ERROR,
                    Response.Status.INTERNAL_SERVER_ERROR.getReasonPhrase(), e, true, LOG);
        } catch (Throwable throwable) {
            ScopeUtils.handleErrorResponse(Response.Status.INTERNAL_SERVER_ERROR,
                    Response.Status.INTERNAL_SERVER_ERROR.getReasonPhrase(), throwable, true, LOG);
        }
        return Response.status(Response.Status.OK).entity(updatedScope).build();
    }

    /**
     * Delete the scope for the given scope name.
     *
     * @param name Name of the scope which need to get deleted.
     * @return Response with the status of scope deletion.
     */
    @Override
    public Response deleteScope(String name) {

        try {
            validateDeleteRequest(name);
            ScopeUtils.getOAuth2ScopeService().deleteScope(name);
        } catch (IdentityOAuth2ScopeClientException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Client Error while deleting scope " + name, e);
            }
            if (Oauth2ScopeConstants.ErrorMessages.ERROR_CODE_NOT_FOUND_SCOPE.getCode()
                    .equals(e.getErrorCode())) {
                ScopeUtils.handleErrorResponse(Response.Status.NOT_FOUND,
                        Response.Status.NOT_FOUND.getReasonPhrase(), e, false, LOG);
            } else if (Oauth2ScopeConstants.ErrorMessages.ERROR_CODE_NOT_AUTHORIZED_DELETE_INTERNAL_SCOPE.getCode()
                    .equals(e.getErrorCode())) {
                ScopeUtils.handleErrorResponse(Response.Status.FORBIDDEN,
                        Response.Status.FORBIDDEN.getReasonPhrase(), e, false, LOG);
            } else {
                ScopeUtils.handleErrorResponse(Response.Status.BAD_REQUEST,
                        Response.Status.BAD_REQUEST.getReasonPhrase(), e, false, LOG);
            }
        } catch (IdentityOAuth2ScopeException e) {
            ScopeUtils.handleErrorResponse(Response.Status.INTERNAL_SERVER_ERROR,
                    Response.Status.INTERNAL_SERVER_ERROR.getReasonPhrase(), e, true, LOG);
        } catch (Throwable throwable) {
            ScopeUtils.handleErrorResponse(Response.Status.INTERNAL_SERVER_ERROR,
                    Response.Status.INTERNAL_SERVER_ERROR.getReasonPhrase(), throwable, true, LOG);
        }
        return Response.status(Response.Status.OK).build();
    }

    /**
     * Build the complete URI to the location of the resource.
     * Ex: https://localhost:9443/t/<tenant-domain>/identity/oauth2/v1.0/scopes/name/<scope_name>
     *
     * @param scopeName Name of the scope.
     * @return Fully qualified and complete URI.
     */
    private static URI buildURIForHeader(String scopeName) {

        URI location;
        String context = IdentityTenantUtil.isTenantQualifiedUrlsEnabled() ? SERVER_API_PATH_COMPONENT + scopeName :
                String.format(TENANT_CONTEXT_PATH_COMPONENT, getTenantDomainFromContext()) + SERVER_API_PATH_COMPONENT
                        + scopeName;
        try {
            String url = ServiceURLBuilder.create().addPath(context).build().getAbsolutePublicURL();
            location = URI.create(url);
        } catch (URLBuilderException e) {
            throw new RuntimeException("Error occurred while building URL in tenant qualified mode.", e);
        }
        return location;
    }

    /**
     * Retrieves loaded tenant domain from carbon context.
     *
     * @return tenant domain of the request being served.
     */
    private static String getTenantDomainFromContext() {

        String tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        if (IdentityUtil.threadLocalProperties.get().get(TENANT_NAME_FROM_CONTEXT) != null) {
            tenantDomain = (String) IdentityUtil.threadLocalProperties.get().get(TENANT_NAME_FROM_CONTEXT);
        }
        return tenantDomain;
    }

    private void validateAddRequest(ScopeDTO scope) throws IdentityOAuth2ScopeClientException {

        if (scope.getName() != null && scope.getName().startsWith(INTERNAL_SCOPE_PREFIX)) {
            String authenticatedUser = PrivilegedCarbonContext.getThreadLocalCarbonContext().getUsername();
            boolean userAuthorized = isUserAuthorized(authenticatedUser);
            if (!userAuthorized) {
                throw new IdentityOAuth2ScopeClientException(
                        Oauth2ScopeConstants.ErrorMessages.ERROR_CODE_NOT_AUTHORIZED_ADD_INTERNAL_SCOPE.getCode(),
                        String.format(Oauth2ScopeConstants.ErrorMessages.ERROR_CODE_NOT_AUTHORIZED_ADD_INTERNAL_SCOPE
                                .getMessage(), authenticatedUser));
            }
        }
    }

    private void validateUpdateRequest(String scopeName) throws IdentityOAuth2ScopeClientException {

        if (scopeName != null && scopeName.startsWith(INTERNAL_SCOPE_PREFIX)) {
            String authenticatedUser = PrivilegedCarbonContext.getThreadLocalCarbonContext().getUsername();
            boolean userAuthorized = isUserAuthorized(authenticatedUser);
            if (!userAuthorized) {
                throw new IdentityOAuth2ScopeClientException(
                        Oauth2ScopeConstants.ErrorMessages.ERROR_CODE_NOT_AUTHORIZED_UPDATE_INTERNAL_SCOPE.getCode(),
                        String.format(Oauth2ScopeConstants.ErrorMessages.ERROR_CODE_NOT_AUTHORIZED_UPDATE_INTERNAL_SCOPE
                                .getMessage(), authenticatedUser));
            }
        }
    }

    private void validateDeleteRequest(String scopeName) throws IdentityOAuth2ScopeClientException {

        if (scopeName != null && scopeName.startsWith(INTERNAL_SCOPE_PREFIX)) {
            String authenticatedUser = PrivilegedCarbonContext.getThreadLocalCarbonContext().getUsername();
            boolean userAuthorized = isUserAuthorized(authenticatedUser);
            if (!userAuthorized) {
                throw new IdentityOAuth2ScopeClientException(
                        Oauth2ScopeConstants.ErrorMessages.ERROR_CODE_NOT_AUTHORIZED_DELETE_INTERNAL_SCOPE.getCode(),
                        String.format(Oauth2ScopeConstants.ErrorMessages.ERROR_CODE_NOT_AUTHORIZED_DELETE_INTERNAL_SCOPE
                                .getMessage(), authenticatedUser));
            }
        }
    }

    private boolean isUserAuthorized(String authenticatedUser) {

        try {
            AuthorizationManager authorizationManager =
                    CarbonContext.getThreadLocalCarbonContext().getUserRealm().getAuthorizationManager();
            return authorizationManager.isUserAuthorized(authenticatedUser,
                    CarbonConstants.UI_ADMIN_PERMISSION_COLLECTION, CarbonConstants.UI_PERMISSION_ACTION);
        } catch (UserStoreException e) {
            LOG.error("Error while validating user authorization of user: " + authenticatedUser, e);
        }
        return false;
    }
}
