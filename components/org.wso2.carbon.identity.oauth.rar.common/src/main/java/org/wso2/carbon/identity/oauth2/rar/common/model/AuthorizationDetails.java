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

package org.wso2.carbon.identity.oauth2.rar.common.model;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.oauth2.rar.common.util.AuthorizationDetailsCommonUtils;
import org.wso2.carbon.identity.oauth2.rar.common.util.AuthorizationDetailsConstants;

import java.io.Serializable;
import java.util.Collections;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Represents a set of {@link AuthorizationDetail} objects which specifies the authorization requirements for a
 * specific resource type within the {@code authorization_details} request parameter used in OAuth 2.0 flows
 * (as defined in RFC 9396: <a href="https://www.rfc-editor.org/rfc/rfc9396.html"> OAuth 2.0 Rich Authorization
 * Requests</a>).
 *
 * <p> Refer to <a href="https://www.rfc-editor.org/rfc/rfc9396#name-request-parameter-authoriza">
 * OAuth 2.0 Rich Authorization Requests </a> for detailed information on the Authorization Details structure. </p>
 *
 * @see AuthorizationDetail
 */
public class AuthorizationDetails implements Serializable {

    private static final long serialVersionUID = -663187547075070618L;

    private final Set<AuthorizationDetail> authorizationDetails;

    /**
     * Constructs an empty set of {@link AuthorizationDetail}.
     */
    public AuthorizationDetails() {
        this(Collections.emptySet());
    }

    /**
     * Constructs an immutable set of {@link AuthorizationDetail}.
     *
     * @param authorizationDetails The set of authorization details. If null, an empty set is assigned.
     */
    public AuthorizationDetails(final Set<AuthorizationDetail> authorizationDetails) {
        this.authorizationDetails = Optional.ofNullable(authorizationDetails)
                .map(Collections::unmodifiableSet)
                .orElse(Collections.emptySet());
    }

    /**
     * Constructs an immutable set of {@link AuthorizationDetail} from a JSON string.
     *
     * @param authorizationDetailsJson The JSON string representing the authorization details.
     */
    public AuthorizationDetails(final String authorizationDetailsJson) {
        this(AuthorizationDetailsCommonUtils.fromJSONArray(
                authorizationDetailsJson, AuthorizationDetail.class, new ObjectMapper()));
    }

    /**
     * Returns a set of the {@code authorization_details}.
     *
     * @return A set of {@link AuthorizationDetail}.
     */
    public Set<AuthorizationDetail> getDetails() {
        return this.authorizationDetails;
    }

    /**
     * Returns a set of the {@code authorization_details} filtered by provided type.
     *
     * @return A set of {@link AuthorizationDetail}.
     */
    public Set<AuthorizationDetail> getDetailsByType(final String type) {
        return this.stream()
                .filter(Objects::nonNull)
                .filter(authorizationDetail -> StringUtils.equals(authorizationDetail.getType(), type))
                .collect(Collectors.toSet());
    }

    /**
     * Converts the current set of authorization details to a JSON string.
     *
     * @return The JSON representation of the authorization details.
     */
    public String toJsonString() {
        return AuthorizationDetailsCommonUtils.toJSON(this.getDetails(), new ObjectMapper());
    }

    /**
     * Converts the set of authorization details to a human-readable string.
     * Each detail's consent description is obtained or the type if the description is unavailable.
     *
     * @return A string representing the authorization details in a human-readable format.
     */
    public String toReadableText() {

        return this.stream()
                .map(authorizationDetail ->
                        authorizationDetail.getConsentDescriptionOrDefault(AuthorizationDetail::getType))
                .collect(Collectors.joining(AuthorizationDetailsConstants.PARAM_SEPARATOR));
    }

    public Stream<AuthorizationDetail> stream() {
        return this.getDetails().stream();
    }
}
