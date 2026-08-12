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

import io.vertx.core.Vertx;
import io.vertx.core.json.DecodeException;
import io.vertx.core.json.JsonObject;
import io.vertx.json.schema.Draft;
import io.vertx.json.schema.JsonSchema;
import io.vertx.json.schema.JsonSchemaOptions;
import io.vertx.json.schema.JsonSchemaValidationException;
import io.vertx.json.schema.OutputFormat;
import io.vertx.json.schema.OutputUnit;
import io.vertx.json.schema.SchemaRepository;
import io.vertx.json.schema.Validator;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.rar.exception.AuthorizationDetailsProcessingException;
import org.wso2.carbon.identity.oauth.rar.model.AuthorizationDetail;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.wso2.carbon.identity.oauth.rar.util.AuthorizationDetailsConstants.SCHEMA_VALIDATION_FAILED_ERR_MSG_FORMAT;
import static org.wso2.carbon.identity.oauth.rar.util.AuthorizationDetailsConstants.TYPE_VALIDATION_FAILED_ERR_MSG_FORMAT;
import static org.wso2.carbon.identity.oauth.rar.util.AuthorizationDetailsConstants.VALIDATION_FAILED_ERR_MSG;

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
public class AuthorizationDetailsSchemaValidatorImpl implements AuthorizationDetailsSchemaValidator {

    private static final Log log = LogFactory.getLog(AuthorizationDetailsSchemaValidatorImpl.class);

    private static final String ADDITIONAL_PROPERTIES = "additionalProperties";
    private static final String BASE_URI = "https://wso2.com/identity-server/schemas";
    private static final Set<String> NON_NEGATIVE_INTEGER_SCHEMA_KEYWORDS = Set.of("minItems", "maxItems",
            "minLength", "maxLength", "minProperties", "maxProperties");

    private static volatile AuthorizationDetailsSchemaValidator instance;
    private final JsonSchemaOptions jsonSchemaOptions;
    private final SchemaRepository schemaRepository;

    private AuthorizationDetailsSchemaValidatorImpl() {

        this.jsonSchemaOptions = new JsonSchemaOptions()
                .setBaseUri(BASE_URI)
                .setDraft(Draft.DRAFT202012)
                .setOutputFormat(OutputFormat.Basic);

        this.schemaRepository = SchemaRepository.create(this.jsonSchemaOptions)
                .preloadMetaSchema(Vertx.vertx().fileSystem());
    }

    public static AuthorizationDetailsSchemaValidator getInstance() {

        if (instance == null) {
            synchronized (AuthorizationDetailsSchemaValidator.class) {
                if (instance == null) {
                    instance = new AuthorizationDetailsSchemaValidatorImpl();
                }
            }
        }
        return instance;
    }

    /**
     * Validates whether the given schema is compliant with the JSON schema DRAFT202012 standard.
     *
     * @param schema the JSON schema as a string.
     * @return true if the schema is valid, false if the schema is invalid or empty.
     * @throws AuthorizationDetailsProcessingException if the validation fails or an error occurs during validation.
     */
    public boolean isValidSchema(final String schema) throws AuthorizationDetailsProcessingException {

        if (StringUtils.isEmpty(schema)) {
            log.debug("Schema validation failed. Schema cannot be null");
            return false;
        }

        final OutputUnit outputUnit = this.buildOutputUnit(null, this.parseJsonObject(schema));
        try {
            // Validates the schema itself against the DRAFT202012 schema standard
            outputUnit.checkValidity();
        } catch (JsonSchemaValidationException e) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Validation failed against DRAFT202012 schema for input: %s. Caused by, ",
                        schema), e);
            }
            throw new AuthorizationDetailsProcessingException(String.format(SCHEMA_VALIDATION_FAILED_ERR_MSG_FORMAT,
                    buildSchemaValidationErrorMessage(outputUnit, e)), e);
        }
        return true;
    }

    private OutputUnit buildOutputUnit(final JsonObject jsonSchema, final JsonObject jsonInput) {

        // Validate the jsonSchema if present, otherwise validate the schema itself against json-schema DRAFT202012
        final Validator validator = (jsonSchema != null)
                ? this.schemaRepository.validator(JsonSchema.of(jsonSchema), this.jsonSchemaOptions)
                : this.schemaRepository.validator(this.jsonSchemaOptions.getDraft().getIdentifier());

        return validator.validate(jsonInput);
    }

    /**
     * Converts a JSON string into a {@link JsonObject}. If the input is invalid, throws an exception.
     *
     * @param jsonString The input JSON string to be converted.
     * @return A {@link JsonObject} created from the input string.
     * @throws AuthorizationDetailsProcessingException if the input string is not valid JSON.
     */
    private JsonObject parseJsonObject(final String jsonString) throws AuthorizationDetailsProcessingException {

        try {
            return new JsonObject(jsonString);
        } catch (DecodeException e) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Failed to parse the JSON input: '%s'. Caused by, ", jsonString), e);
            }
            throw new AuthorizationDetailsProcessingException(
                    String.format("%s. Invalid JSON input received.", VALIDATION_FAILED_ERR_MSG), e);
        }
    }

    private String buildSchemaValidationErrorMessage(final OutputUnit outputUnit,
                                                     final JsonSchemaValidationException ex) {

        // Extract the last validation error if available, otherwise use exception message.
        if (outputUnit == null || CollectionUtils.isEmpty(outputUnit.getErrors())) {
            return ex.getMessage();
        }
        final OutputUnit lastError = outputUnit.getErrors().get(outputUnit.getErrors().size() - 1);
        return lastError.getInstanceLocation() + StringUtils.SPACE + lastError.getError();
    }

    /**
     * Validates whether the given authorization detail complies with the provided JSON schema.
     *
     * @param schema              the JSON schema as a string.
     * @param authorizationDetail the authorization detail to be validated.
     * @return true if the authorization detail is schema compliant, false if schema or authorizationDetail is invalid.
     * @throws AuthorizationDetailsProcessingException if the validation fails or an error occurs during validation.
     */
    public boolean isSchemaCompliant(final String schema, final AuthorizationDetail authorizationDetail)
            throws AuthorizationDetailsProcessingException {

        if (StringUtils.isEmpty(schema) || authorizationDetail == null) {
            log.debug("Schema validation failed. Inputs cannot be null");
            return false;
        }

        return this.isSchemaCompliant(this.parseJsonObject(schema), authorizationDetail);
    }

    public boolean isSchemaCompliant(final JsonObject schema, final AuthorizationDetail authorizationDetail)
            throws AuthorizationDetailsProcessingException {

        if (schema == null || authorizationDetail == null) {
            log.debug("Schema validation failed. Inputs cannot be null");
            return false;
        }

        final OutputUnit outputUnit =
                this.buildOutputUnit(schema, this.parseJsonObject(authorizationDetail.toJsonString()));

        try {
            // Validates the authorization detail against the schema
            outputUnit.checkValidity();
        } catch (JsonSchemaValidationException e) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Schema validation failed for authorization details type: %s. Caused by, ",
                        authorizationDetail.getType()), e);
            }
            throw new AuthorizationDetailsProcessingException(String.format(TYPE_VALIDATION_FAILED_ERR_MSG_FORMAT,
                    authorizationDetail.getType(), this.buildSchemaValidationErrorMessage(outputUnit, e)), e);
        }
        return true;
    }

    public boolean isSchemaCompliant(final Map<String, Object> schema, final AuthorizationDetail authorizationDetail)
            throws AuthorizationDetailsProcessingException {

        if (MapUtils.isEmpty(schema) || authorizationDetail == null) {
            log.debug("Schema validation failed. Inputs cannot be null");
            return false;
        }

        final JsonObject jsonSchema = new JsonObject(this.normalizeSchemaMap(schema));
        jsonSchema.put(ADDITIONAL_PROPERTIES, false); // Ensure no unknown fields are allowed

        return this.isSchemaCompliant(jsonSchema, authorizationDetail);
    }

    private Map<String, Object> normalizeSchemaMap(final Map<String, Object> schema) {

        final Map<String, Object> normalizedSchema = new HashMap<>();
        for (Map.Entry<String, Object> entry : schema.entrySet()) {
            normalizedSchema.put(entry.getKey(), this.normalizeSchemaValue(entry.getKey(), entry.getValue()));
        }
        return normalizedSchema;
    }

    @SuppressWarnings("unchecked")
    private Object normalizeSchemaValue(final String key, final Object value) {

        if (NON_NEGATIVE_INTEGER_SCHEMA_KEYWORDS.contains(key)) {
            return this.normalizeNonNegativeIntegerSchemaKeyword(value);
        }
        if (value instanceof Map) {
            return this.normalizeSchemaMap((Map<String, Object>) value);
        }
        if (value instanceof Collection) {
            return this.normalizeSchemaCollection((Collection<?>) value);
        }
        return value;
    }

    @SuppressWarnings("unchecked")
    private List<Object> normalizeSchemaCollection(final Collection<?> values) {

        final List<Object> normalizedValues = new ArrayList<>(values.size());
        for (Object value : values) {
            if (value instanceof Map) {
                normalizedValues.add(this.normalizeSchemaMap((Map<String, Object>) value));
            } else if (value instanceof Collection) {
                normalizedValues.add(this.normalizeSchemaCollection((Collection<?>) value));
            } else {
                normalizedValues.add(value);
            }
        }
        return normalizedValues;
    }

    private Object normalizeNonNegativeIntegerSchemaKeyword(final Object value) {

        if (!(value instanceof Number)) {
            return value;
        }

        final Number number = (Number) value;
        if (number instanceof Integer) {
            return number;
        }
        if (number instanceof Byte || number instanceof Short) {
            final int intValue = number.intValue();
            return intValue >= 0 ? intValue : value;
        }
        if (number instanceof Long) {
            final long longValue = number.longValue();
            return longValue >= 0 && longValue <= Integer.MAX_VALUE ? (int) longValue : value;
        }
        if (number instanceof BigInteger) {
            return this.normalizeBigInteger((BigInteger) number, value);
        }
        if (number instanceof BigDecimal) {
            try {
                return this.normalizeBigInteger(((BigDecimal) number).toBigIntegerExact(), value);
            } catch (ArithmeticException e) {
                return value;
            }
        }

        final double doubleValue = number.doubleValue();
        if (Double.isFinite(doubleValue) && doubleValue >= 0 && doubleValue <= Integer.MAX_VALUE
                && doubleValue == Math.rint(doubleValue)) {
            return (int) doubleValue;
        }
        return value;
    }

    private Object normalizeBigInteger(final BigInteger integerValue, final Object originalValue) {

        if (integerValue.signum() >= 0 && integerValue.compareTo(BigInteger.valueOf(Integer.MAX_VALUE)) <= 0) {
            return integerValue.intValue();
        }
        return originalValue;
    }
}
