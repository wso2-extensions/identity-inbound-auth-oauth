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

package org.wso2.carbon.identity.oauth.rar.util;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.rar.model.AuthorizationDetail;
import org.wso2.carbon.identity.oauth.rar.model.AuthorizationDetails;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.wso2.carbon.identity.oauth.rar.util.AuthorizationDetailsConstants.EMPTY_JSON_ARRAY;
import static org.wso2.carbon.identity.oauth.rar.util.AuthorizationDetailsConstants.EMPTY_JSON_OBJECT;

/**
 * Utility class for handling OAuth2 Rich Authorization Requests.
 */
public class AuthorizationDetailsCommonUtils {

    private static final Log log = LogFactory.getLog(AuthorizationDetailsCommonUtils.class);

    private static volatile ObjectMapper objectMapper;
    private static final TypeReference<Map<String, Object>> TYPE_MAP = new TypeReference<Map<String, Object>>() { };

    private AuthorizationDetailsCommonUtils() {
        // Private constructor to prevent instantiation
    }

    /**
     * Parses the given JSON array string into a set of {@link AuthorizationDetail} objects.
     *
     * @param authorizationDetailsJson A JSON string containing authorization details which comes in the
     *                                 OAuth 2.0 authorization request or token request
     * @param clazz                    A Class that extends {@link AuthorizationDetail} to be parsed
     * @param <T>                      the type parameter extending {@code AuthorizationDetail}
     * @return an immutable set of {@link AuthorizationDetail} objects parsed from the given JSON string,
     * or an empty set if parsing fails
     * @see AuthorizationDetails
     */
    public static <T extends AuthorizationDetail> Set<T> fromJSONArray(final String authorizationDetailsJson,
                                                                       final Class<T> clazz) {

        try {
            if (StringUtils.isNotEmpty(authorizationDetailsJson)) {
                return getDefaultObjectMapper().readValue(authorizationDetailsJson,
                        getDefaultObjectMapper().getTypeFactory().constructCollectionType(Set.class, clazz));
            }
        } catch (JsonProcessingException e) {
            log.debug("Error occurred while parsing String to AuthorizationDetails. Caused by, ", e);
        }
        return new HashSet<>();
    }

    /**
     * Parses the given JSON object string into an {@link AuthorizationDetail} object.
     *
     * @param authorizationDetailJson A JSON string containing authorization detail object
     * @param clazz                   A Class that extends {@link AuthorizationDetail} to be parsed
     * @param <T>                     the type parameter extending {@code AuthorizationDetail}
     * @return an {@link AuthorizationDetail} objects parsed from the given JSON string,
     * or null if parsing fails
     * @see AuthorizationDetail
     */
    public static <T extends AuthorizationDetail> T fromJSON(final String authorizationDetailJson,
                                                             final Class<T> clazz) {

        try {
            if (StringUtils.isNotEmpty(authorizationDetailJson)) {
                return getDefaultObjectMapper().readValue(authorizationDetailJson, clazz);
            }
        } catch (JsonProcessingException e) {
            log.debug("Error occurred while parsing String to AuthorizationDetails. Caused by, ", e);
        }
        return null;
    }

    /**
     * Converts a set of {@code AuthorizationDetail} objects into a JSON string.
     * <p>
     * If the input set is {@code null} or an exception occurs during the conversion,
     * an empty JSON array ({@code []}) is returned.
     * </p>
     *
     * @param authorizationDetails the set of {@code AuthorizationDetail} objects to convert
     * @param <T>                  the type parameter extending {@code AuthorizationDetail}
     * @return a JSON string representation of the authorization details set,
     * or an empty JSON array if null or an error occurs
     * @see AuthorizationDetail
     * @see AuthorizationDetails
     */
    public static <T extends AuthorizationDetail> String toJSON(final Set<T> authorizationDetails) {

        try {
            if (authorizationDetails != null) {
                return getDefaultObjectMapper().writeValueAsString(authorizationDetails);
            }
        } catch (JsonProcessingException e) {
            log.debug("Error occurred while parsing AuthorizationDetails to String. Caused by, ", e);
        }
        return EMPTY_JSON_ARRAY;
    }

    /**
     * Converts a single {@code AuthorizationDetail} object into a JSON string.
     * <p>
     * If the input object is {@code null} or an exception occurs during the conversion,
     * an empty JSON object ({@code {}}) is returned.
     * </p>
     *
     * @param authorizationDetail the {@code AuthorizationDetail} object to convert
     * @param <T>                 the type parameter extending {@code AuthorizationDetail}
     * @return a JSON string representation of the authorization detail,
     * or an empty JSON object if null or an error occurs
     * @see AuthorizationDetail
     * @see AuthorizationDetails
     */
    public static <T extends AuthorizationDetail> String toJSON(final T authorizationDetail) {

        try {
            if (authorizationDetail != null) {
                return getDefaultObjectMapper().writeValueAsString(authorizationDetail);
            }
        } catch (JsonProcessingException e) {
            log.debug("Error occurred while parsing AuthorizationDetail to String. Caused by, ", e);
        }
        return EMPTY_JSON_OBJECT;
    }

    /**
     * Converts a single {@code AuthorizationDetail} object into a {@link Map}.
     * <p>
     * If the input object is {@code null} or an exception occurs during the conversion,
     * an empty {@link HashMap} is returned.
     * </p>
     *
     * @param authorizationDetail the {@code AuthorizationDetail} object to convert
     * @param <T>                 the type parameter extending {@code AuthorizationDetail}
     * @return a {@code Map} representation of the authorization detail,
     * or an empty {@code HashMap} if null or an error occurs
     * @see AuthorizationDetail
     * @see AuthorizationDetails
     */
    public static <T extends AuthorizationDetail> Map<String, Object> toMap(final T authorizationDetail) {

        return (authorizationDetail == null) ? Collections.emptyMap()
                : getDefaultObjectMapper().convertValue(authorizationDetail, TYPE_MAP);
    }

    /**
     * Returns a configured default {@link ObjectMapper} instance.
     *
     * <p>This singleton ObjectMapper is configured to exclude properties with null values from the JSON output.
     *
     * @return a configured {@link ObjectMapper} instance.
     */
    public static ObjectMapper getDefaultObjectMapper() {
        if (objectMapper == null) {
            synchronized (AuthorizationDetailsCommonUtils.class) {
                if (objectMapper == null) {
                    objectMapper = new ObjectMapper();
                    objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
                }
            }
        }
        return objectMapper;
    }
}
