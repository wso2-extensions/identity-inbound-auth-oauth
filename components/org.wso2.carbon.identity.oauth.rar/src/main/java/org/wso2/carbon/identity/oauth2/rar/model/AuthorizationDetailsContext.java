/*
 * Copyright (c) 2024, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.oauth2.rar.common.model.AuthorizationDetail;

import java.util.Objects;

/**
 * Represents the context for rich authorization requests in an OAuth2 flow.
 * <p>
 * This class holds relevant details such as OAuth2 parameters, application details, the authenticated user,
 * and specific authorization details. It is immutable to ensure that the context remains consistent throughout its use.
 * </p>
 */
public class AuthorizationDetailsContext {

    private final OAuth2Parameters oAuth2Parameters;
    private final OAuthAppDO oAuthAppDO;
    private final AuthenticatedUser authenticatedUser;
    private final AuthorizationDetail authorizationDetail;

    /**
     * Constructs a new {@code AuthorizationDetailsContext}.
     * <p>
     * This constructor ensures that all necessary details for an authorization context are provided.
     * </p>
     *
     * @param oAuth2Parameters    the OAuth2 parameters.
     * @param oAuthAppDO          the OAuth application details.
     * @param authenticatedUser   the authenticated user.
     * @param authorizationDetail the specific authorization detail.
     * @throws NullPointerException if any of the arguments are {@code null}.
     */
    public AuthorizationDetailsContext(final OAuth2Parameters oAuth2Parameters, final OAuthAppDO oAuthAppDO,
                                       final AuthenticatedUser authenticatedUser,
                                       final AuthorizationDetail authorizationDetail) {
        this.oAuth2Parameters = Objects.requireNonNull(oAuth2Parameters, "oAuth2Parameters cannot be null");
        this.oAuthAppDO = Objects.requireNonNull(oAuthAppDO, "oAuthAppDO cannot be null");
        this.authenticatedUser = Objects.requireNonNull(authenticatedUser, "authenticatedUser cannot be null");
        this.authorizationDetail = Objects.requireNonNull(authorizationDetail, "authorizationDetail cannot be null");
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
     * Returns the OAuth2 parameters.
     *
     * @return the {@link OAuth2Parameters} instance.
     */
    public OAuth2Parameters getOAuth2Parameters() {
        return this.oAuth2Parameters;
    }

    /**
     * Returns the OAuth application details.
     *
     * @return the {@link OAuthAppDO} instance.
     */
    public OAuthAppDO getoAuthAppDO() {
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
}
