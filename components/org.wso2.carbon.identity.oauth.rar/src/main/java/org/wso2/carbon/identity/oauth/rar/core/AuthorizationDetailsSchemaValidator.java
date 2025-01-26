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

package org.wso2.carbon.identity.oauth.rar.core;

import io.vertx.core.json.JsonObject;
import io.vertx.json.schema.JsonSchema;
import org.wso2.carbon.identity.oauth.rar.exception.AuthorizationDetailsProcessingException;
import org.wso2.carbon.identity.oauth.rar.model.AuthorizationDetail;

import java.util.Map;

/**
 * The {@code AuthorizationDetailsSchemaValidator} is responsible for validating authorization details
 * against a provided JSON schema.
 * <p>
 * This class supports both validation of custom schemas provided as input and validation of default schemas
 * based on the DRAFT202012 standard.
 * <p>
 * Typical usage:
 * <pre>
 *     AuthorizationDetailsSchemaValidator validator = AuthorizationDetailsSchemaValidator.getInstance();
 *     boolean isValid = validator.isSchemaCompliant(schemaString, authorizationDetail);
 * </pre>
 *
 * <p> Refer to <a href="https://json-schema.org/draft/2020-12/draft-bhutton-json-schema-01">
 * json-schema </a> for detailed information on the JSON documents structure. </p>
 *
 * @see AuthorizationDetail
 * @see JsonSchema
 */
public interface AuthorizationDetailsSchemaValidator {

    /**
     * Validates whether the given schema is compliant with the JSON schema DRAFT202012 standard.
     *
     * @param schema the JSON schema as a string.
     * @return true if the schema is valid, false if the schema is invalid or empty.
     * @throws AuthorizationDetailsProcessingException if the validation fails or an error occurs during validation.
     */
    boolean isValidSchema(final String schema) throws AuthorizationDetailsProcessingException;

    /**
     * Validates whether the given authorization detail complies with the provided JSON schema.
     *
     * @param schema              the JSON schema as a {@code string}.
     * @param authorizationDetail the authorization detail to be validated.
     * @return true if the authorization detail is schema compliant, false if schema or authorizationDetail is invalid.
     * @throws AuthorizationDetailsProcessingException if the validation fails or an error occurs during validation.
     */
    boolean isSchemaCompliant(final String schema, final AuthorizationDetail authorizationDetail)
            throws AuthorizationDetailsProcessingException;

    /**
     * Validates whether the given authorization detail complies with the provided JSON schema.
     *
     * @param schema              the JSON schema as a {@code Map<String, Object>}.
     * @param authorizationDetail the authorization detail to be validated.
     * @return true if the authorization detail is schema compliant, false if schema or authorizationDetail is invalid.
     * @throws AuthorizationDetailsProcessingException if the validation fails or an error occurs during validation.
     */
    boolean isSchemaCompliant(final Map<String, Object> schema, final AuthorizationDetail authorizationDetail)
            throws AuthorizationDetailsProcessingException;

    /**
     * Validates whether the given authorization detail complies with the provided JSON schema.
     *
     * @param schema              the JSON schema as a {@link JsonObject}.
     * @param authorizationDetail the authorization detail to be validated.
     * @return true if the authorization detail is schema compliant, false if schema or authorizationDetail is invalid.
     * @throws AuthorizationDetailsProcessingException if the validation fails or an error occurs during validation.
     */
    boolean isSchemaCompliant(final JsonObject schema, final AuthorizationDetail authorizationDetail)
            throws AuthorizationDetailsProcessingException;
}
