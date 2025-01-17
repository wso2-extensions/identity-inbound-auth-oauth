/*
 * Copyright (c) 2025, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.rar.model;

import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.AuthorizationDetailsType;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;

import java.util.Objects;

import javax.servlet.http.HttpServletRequestWrapper;

import static org.wso2.carbon.identity.oauth2.authz.AuthorizationHandlerManager.OAUTH_APP_PROPERTY;

/**
 * Represents the context for rich authorization requests in an OAuth2 flow.
 * <p>
 * This class holds relevant details such as OAuth2 parameters, application details, the authenticated user,
 * and specific authorization details. It is immutable to ensure that the context remains consistent throughout its use.
 * </p>
 */
public class AuthorizationDetailsContext {

    private final AuthenticatedUser authenticatedUser;
    private final AuthorizationDetail authorizationDetail;
    private final AuthorizationDetailsType authorizationDetailsType;
    private final HttpServletRequestWrapper httpServletRequestWrapper;
    private final OAuthAppDO oAuthAppDO;
    private final String[] scopes;

    /**
     * Constructs a new {@code AuthorizationDetailsContext}.
     *
     * @param authorizationDetail         the specific {@link AuthorizationDetail} to be validated.
     * @param oAuthAuthzReqMessageContext the {@link OAuthAuthzReqMessageContext} instance which represent
     *                                    the authorization request context.
     * @throws NullPointerException if any of the arguments are {@code null}.
     */
    public AuthorizationDetailsContext(final AuthorizationDetail authorizationDetail,
                                       final AuthorizationDetailsType authorizationDetailsType,
                                       final OAuthAuthzReqMessageContext oAuthAuthzReqMessageContext) {

        this(oAuthAuthzReqMessageContext.getAuthorizationReqDTO().getUser(),
                authorizationDetail,
                authorizationDetailsType,
                oAuthAuthzReqMessageContext.getAuthorizationReqDTO().getHttpServletRequestWrapper(),
                (OAuthAppDO) oAuthAuthzReqMessageContext.getProperty(OAUTH_APP_PROPERTY),
                oAuthAuthzReqMessageContext.getAuthorizationReqDTO().getScopes());
    }

    /**
     * Constructs a new {@code AuthorizationDetailsContext}.
     * <p>
     * This constructor ensures that all necessary details for an authorization context are provided.
     * </p>
     *
     * @param authenticatedUser         the {@link AuthenticatedUser}.
     * @param authorizationDetail       the specific {@link AuthorizationDetail} to be validated.
     * @param httpServletRequestWrapper the {@link HttpServletRequestWrapper} instance containing request details.
     * @param oAuthAppDO                the {@link OAuthAppDO} containing application details.
     * @param scopes                    the array of scopes requested.
     * @throws NullPointerException if any of the arguments are {@code null}.
     */
    public AuthorizationDetailsContext(final AuthenticatedUser authenticatedUser,
                                       final AuthorizationDetail authorizationDetail,
                                       final AuthorizationDetailsType authorizationDetailsType,
                                       final HttpServletRequestWrapper httpServletRequestWrapper,
                                       final OAuthAppDO oAuthAppDO,
                                       final String[] scopes) {

        this.authenticatedUser = Objects.requireNonNull(authenticatedUser, "authenticatedUser cannot be null");
        this.authorizationDetail = Objects.requireNonNull(authorizationDetail, "authorizationDetail cannot be null");
        this.authorizationDetailsType =
                Objects.requireNonNull(authorizationDetailsType, "authorizationDetailsType cannot be null");
        this.httpServletRequestWrapper =
                Objects.requireNonNull(httpServletRequestWrapper, "httpServletRequestWrapper cannot be null");
        this.oAuthAppDO = Objects.requireNonNull(oAuthAppDO, "oAuthAppDO cannot be null");
        this.scopes = Objects.requireNonNull(scopes, "scopes cannot be null");
    }

    /**
     * Constructs a new {@code AuthorizationDetailsContext}.
     *
     * @param authorizationDetail         the specific {@link AuthorizationDetail} to be validated.
     * @param oAuthTokenReqMessageContext the {@link OAuthTokenReqMessageContext} instance which represent
     *                                    the token request context.
     * @throws NullPointerException if any of the arguments are {@code null}.
     */
    public AuthorizationDetailsContext(final AuthorizationDetail authorizationDetail,
                                       final AuthorizationDetailsType authorizationDetailsType,
                                       final OAuthTokenReqMessageContext oAuthTokenReqMessageContext) {

        this(oAuthTokenReqMessageContext.getAuthorizedUser(),
                authorizationDetail,
                authorizationDetailsType,
                oAuthTokenReqMessageContext.getOauth2AccessTokenReqDTO().getHttpServletRequestWrapper(),
                (OAuthAppDO) oAuthTokenReqMessageContext.getProperty(OAUTH_APP_PROPERTY),
                oAuthTokenReqMessageContext.getScope());
    }

    /**
     * Returns the {@code AuthorizationDetail} instance.
     *
     * @return the {@link AuthorizationDetail} instance.
     */
    public AuthorizationDetail getAuthorizationDetail() {
        return this.authorizationDetail;
    }

    /**
     * Returns the {@code AuthorizationDetailsType} instance.
     *
     * @return the {@link AuthorizationDetailsType} instance.
     */
    public AuthorizationDetailsType getAuthorizationDetailsType() {
        return this.authorizationDetailsType;
    }

    /**
     * Returns the OAuth application details.
     *
     * @return the {@link OAuthAppDO} instance.
     */
    public OAuthAppDO getOAuthAppDO() {
        return this.oAuthAppDO;
    }

    /**
     * Returns the authenticated user.
     *
     * @return the {@link AuthenticatedUser} instance.
     */
    public AuthenticatedUser getAuthenticatedUser() {
        return this.authenticatedUser;
    }

    /**
     * Returns the HTTP servlet request user.
     *
     * @return the {@link HttpServletRequestWrapper} instance containing HTTP request details.
     */
    public HttpServletRequestWrapper getHttpServletRequestWrapper() {
        return this.httpServletRequestWrapper;
    }

    /**
     * Returns the valid scopes requested by the client.
     *
     * @return the {@link String} array of scopes.
     */
    public String[] getScopes() {
        return this.scopes;
    }
}
