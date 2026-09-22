/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.util;

import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.ORGANIZATION_LOGIN_IDP_NAME;

/**
 * Utilities for classifying users that reach an application through organization login.
 * <p>
 * These conditions were previously repeated inline at each place that needed them, which allowed the copies to
 * drift apart. One consequence was the id_token and the userinfo endpoint disagreeing on the claims of an
 * organization SSO user, because the code deciding whether to re-resolve claims and the code deciding whether to
 * drop the cached ones classified the same user differently. Callers should use these methods rather than
 * comparing the federated identity provider name directly.
 * <p>
 * The methods depend only on the state of the given user, with no service calls, so they are safe to evaluate
 * anywhere in a token or authorization flow.
 */
public class OrganizationUserUtil {

    private OrganizationUserUtil() {

    }

    /**
     * Check whether the user is federated through the organization login identity provider.
     *
     * @param authenticatedUser Authenticated user.
     * @return true if the user is federated through the organization login identity provider.
     */
    public static boolean isOrganizationLoginUser(AuthenticatedUser authenticatedUser) {

        return authenticatedUser.isFederatedUser()
                && ORGANIZATION_LOGIN_IDP_NAME.equals(authenticatedUser.getFederatedIdPName());
    }

    /**
     * Check whether the user is an organization SSO user, i.e. federated through the organization login identity
     * provider and resident in a known organization. Such a user is federated, but the claims are held in the
     * organization's user store and are therefore resolvable locally.
     *
     * @param authenticatedUser Authenticated user.
     * @return true if the user is an organization SSO user.
     */
    public static boolean isOrganizationSsoUser(AuthenticatedUser authenticatedUser) {

        return isOrganizationLoginUser(authenticatedUser)
                && authenticatedUser.getUserResidentOrganization() != null;
    }
}
