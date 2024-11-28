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

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.oauth2.rar.util.AuthorizationDetailsCommonUtils;

import java.io.Serializable;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * Represents an individual authorization details object which specifies the authorization requirements for a
 * specific resource type within the {@code authorization_details} request parameter used in OAuth 2.0 flows
 * (as defined in RFC 9396: <a href="https://www.rfc-editor.org/rfc/rfc9396.html"> OAuth 2.0 Rich Authorization
 * Requests</a>).
 *
 * <p> This class encapsulates the various attributes and their corresponding values that can be included within an
 * authorization details object. The mandatory {@code type} field identifies the resource type or access requirement
 * being described. </p>
 * <p>
 * Here is an example of {@code authorization_details} with
 * <a href="https://www.rfc-editor.org/rfc/rfc9396.html#name-common-data-fields"> Common Data Fields. </a>
 * <pre> {@code
 * [
 *   {
 *     "type": "customer_information",
 *     "locations": [
 *       "https://example.com/customers"
 *     ],
 *     "actions": [
 *       "read",
 *       "write"
 *     ],
 *     "datatypes": [
 *       "contacts",
 *       "photos"
 *     ],
 *     "identifier":"account-14-32-32-3",
 *     "privileges": [
 *       "admin"
 *     ]
 *   }
 * ]
 * } </pre>
 *
 * <p> Refer to <a href="https://www.rfc-editor.org/rfc/rfc9396#name-request-parameter-authoriza">
 * OAuth 2.0 Rich Authorization Requests </a> for detailed information on the Authorization Details structure. </p>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AuthorizationDetail implements Serializable {

    private static final long serialVersionUID = -3928636285264078857L;

    private String type;
    private List<String> locations;
    private List<String> actions;
    @JsonProperty("datatypes")
    private List<String> dataTypes;
    private String identifier;
    private List<String> privileges;
    private Map<String, Object> details;

    @JsonProperty("_id")
    private String id;
    @JsonProperty("_description")
    private String description;

    /**
     * Gets the unique ID of the authorization detail.
     *
     * @return the ID of the authorization detail.
     */
    public String getId() {

        return this.id;
    }

    /**
     * Sets a unique temporary ID for a given authorization detail instance.
     */
    public void setId(final String id) {

        this.id = id;
    }

    /**
     * Gets the value of the type field associated with the authorization details object.
     *
     * <p> {@code type} is a unique identifier for the authorization details type as a string. The value of the type
     * field determines the allowable contents of the object that contains it. </p>
     *
     * @return The String value of the type field
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc9396#name-authorization-details-types">
     * Authorization Details Types</a>
     */
    public String getType() {

        return this.type;
    }

    public void setType(final String type) {

        this.type = type;
    }

    /**
     * Gets the optional list of locations associated with the authorization details object.
     *
     * <p> {@code locations} is an array of strings representing the location of the resource or RS. These strings are
     * typically URIs identifying the location of the RS. This field can allow a client to specify a particular RS. </p>
     *
     * @return A list of locations or {@code null} if the {@code locations} field is not present.
     */
    public List<String> getLocations() {

        return this.locations;
    }

    public void setLocations(final List<String> locations) {

        this.locations = locations;
    }

    /**
     * Gets the optional list of actions associated with the authorization details object.
     *
     * <p> {@code actions} is an array of strings representing the kinds of actions to be taken at the resource.
     *
     * @return A list of actions or {@code null} if the {@code actions} field is not present.
     */
    public List<String> getActions() {

        return this.actions;
    }

    public void setActions(final List<String> actions) {

        this.actions = actions;
    }

    /**
     * Gets the optional list of data types associated with the authorization details object.
     *
     * <p> {@code datatypes} is an array of strings representing what kinds of data being requested from the resource.
     *
     * @return A list of datatypes or {@code null} if the {@code datatypes} field is not present.
     */
    public List<String> getDataTypes() {

        return this.dataTypes;
    }

    public void setDataTypes(final List<String> dataTypes) {

        this.dataTypes = dataTypes;
    }

    /**
     * Gets the optional String identifier associated with the authorization details object.
     *
     * <p> {@code identifier} is a string identifier indicating a specific resource available at the API.
     *
     * @return The String value of the identifier or {@code null} if the {@code identifier} field is not present.
     */
    public String getIdentifier() {

        return this.identifier;
    }

    public void setIdentifier(final String identifier) {

        this.identifier = identifier;
    }

    /**
     * Gets the optional list of privileges associated with the authorization details object.
     *
     * <p> {@code privileges} is an array of strings representing the types or levels of privilege being requested
     * at the resource.
     *
     * @return The String value of the privileges or {@code null} if the {@code privileges} field is not present.
     */
    public List<String> getPrivileges() {

        return this.privileges;
    }

    public void setPrivileges(final List<String> privileges) {

        this.privileges = privileges;
    }

    /**
     * Gets a map containing API-specific fields from the authorization details object. The presence and structure
     * of these fields can vary depending on the specific API being accessed.
     *
     * @return A map containing API-specific fields or {@code null} if no fields are present.
     */
    @JsonAnyGetter
    public Map<String, Object> getDetails() {

        return this.details;
    }

    public void setDetails(final Map<String, Object> details) {

        this.details = details;
    }

    @JsonAnySetter
    public void setDetail(final String key, final Object value) {

        if (this.details == null) {
            this.setDetails(new HashMap<>());
        }
        this.details.put(key, value);
    }

    /**
     * Returns the consent description of an {@link AuthorizationDetail} instance.
     * This value is only available after the enrichment process. The consent description provides a human-readable
     * representation of the {@code authorization_details}, typically in the form of a sentence derived from the
     * JSON object.
     *
     * @return A string representing the consent description of the {@code authorization_details}.
     */
    public String getDescription() {
        return this.description;
    }

    /**
     * Sets a human-readable sentence that describes the {@code authorization_details}. This sentence is used to
     * display to the user and obtain their consent for the current {@link AuthorizationDetail AuthorizationDetail}.
     *
     * @param description A string representing the description of the authorization detail.
     *                    This description should be clear and understandable to the user,
     *                    explaining what they are consenting to.
     */
    public void setDescription(final String description) {

        this.description = description;
    }

    /**
     * Returns the consent description if present; otherwise, returns a value supplied by the provided {@link Function}.
     * Example usage:
     * <pre> {@code
     * // Example 1: Using a simple default function that returns the "type", if description is missing
     * AuthorizationDetail detail = new AuthorizationDetail();
     * detail.setType("user_information");
     * detail.setConsentDescription(""); // Empty description
     * String result = detail.getConsentDescriptionOrDefault(authDetail -> authDetail.getType());
     * // result will be "user_information"
     *
     * // Example 2: Consent description is already set and not empty
     * AuthorizationDetail detail = new AuthorizationDetail();
     * detail.setType("user_information");
     * detail.setConsentDescription("User consented to data usage");
     * String result = detail.getConsentDescriptionOrDefault(authDetail -> "Default Description");
     * // result will be "User consented to data usage"
     * } </pre>
     *
     * @param defaultFunction the Function that provides a default value if the consent description is not present
     * @return the consent description if present, otherwise the value from the Function
     */
    public String getDescriptionOrDefault(Function<AuthorizationDetail, String> defaultFunction) {

        return StringUtils.isNotEmpty(this.getDescription()) ? this.getDescription() : defaultFunction.apply(this);
    }

    /**
     * Converts the current authorization detail instance to a JSON string.
     *
     * @return The JSON representation of the authorization detail.
     */
    public String toJsonString() {

        return AuthorizationDetailsCommonUtils.toJSON(this);
    }

    /**
     * Converts the current authorization detail instance to a {@link Map}.
     *
     * @return The {@code Map<String, Object>} representation of the authorization detail.
     */
    public Map<String, Object> toMap() {

        return AuthorizationDetailsCommonUtils.toMap(this);
    }

    @Override
    public String toString() {

        return "AuthorizationDetails {" +
                "type='" + this.type + '\'' +
                ", locations=" + this.locations +
                ", actions=" + this.actions +
                ", datatypes=" + this.dataTypes +
                ", identifier=" + this.identifier +
                ", privileges=" + this.privileges +
                ", details=" + this.details +
                '}';
    }
}
