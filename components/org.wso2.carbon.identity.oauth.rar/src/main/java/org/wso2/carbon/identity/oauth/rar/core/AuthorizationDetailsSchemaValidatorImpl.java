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
import io.vertx.core.json.JsonArray;
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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;

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
    private static final List<String> DEREFERENCE_ANNOTATIONS =
            Arrays.asList("__absolute_uri__", "__absolute_ref__", "__absolute_recursive_ref__");
    private static final List<String> DYNAMIC_REF_KEYWORD = Collections.singletonList("$dynamicRef");
    private static final List<String> PROPERTY_NAME_KEYWORDS = Arrays.asList("dependentRequired", "dependencies");
    private static final String ABSOLUTE_REF_ANNOTATION = "__absolute_ref__";
    // Keywords whose subschemas are applied to the same input location as the schema that holds them.
    private static final List<String> IN_PLACE_KEYWORDS = Arrays.asList("not", "if", "then", "else");
    private static final List<String> IN_PLACE_ARRAY_KEYWORDS = Arrays.asList("allOf", "anyOf", "oneOf");
    private static final List<String> IN_PLACE_MAP_KEYWORDS = Arrays.asList("dependentSchemas", "dependencies");

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

    private OutputUnit buildOutputUnit(final JsonObject jsonSchema, final JsonObject jsonInput)
            throws AuthorizationDetailsProcessingException {

        if (jsonSchema != null) {
            final Validator dereferencedValidator = this.buildDereferencedValidator(jsonSchema, jsonInput);
            if (dereferencedValidator != null) {
                return validateDereferenced(dereferencedValidator, jsonInput);
            }
        }

        // Validate the jsonSchema if present, otherwise validate the schema itself against json-schema DRAFT202012
        final Validator validator = (jsonSchema != null)
                ? this.schemaRepository.validator(JsonSchema.of(jsonSchema), this.jsonSchemaOptions)
                : this.schemaRepository.validator(this.jsonSchemaOptions.getDraft().getIdentifier());

        return validator.validate(jsonInput);
    }

    /**
     * Builds a validator that resolves the schema's internal references (e.g. "#/$defs/..."). Returns null when the
     * schema must be validated without dereferencing, as before.
     */
    private Validator buildDereferencedValidator(final JsonObject jsonSchema, final JsonObject jsonInput) {

        if (!canDereference(jsonSchema, jsonInput)) {
            return null;
        }
        try {
            final Validator validator =
                    this.schemaRepository.validator(JsonSchema.of(jsonSchema), this.jsonSchemaOptions, true);
            // Vert.x follows a "$ref" loop that never moves into the input until the stack overflows.
            if (this.hasReferenceLoop(jsonSchema)) {
                log.debug("The authorization details schema has a $ref loop. Validating without dereferencing.");
                return null;
            }
            return validator;
        } catch (RuntimeException e) {
            if (log.isDebugEnabled()) {
                log.debug("Unable to dereference the authorization details schema. " +
                        "Validating without dereferencing.", e);
            }
            return null;
        }
    }

    private static OutputUnit validateDereferenced(final Validator validator, final JsonObject jsonInput)
            throws AuthorizationDetailsProcessingException {

        try {
            return validator.validate(jsonInput);
        } catch (StackOverflowError e) {
            // A recursive schema is applied once per nesting level of the input, so a deeply nested input can
            // exhaust the stack. Reject such an input as invalid.
            log.debug("The authorization details input is nested too deeply to validate against the schema.");
            throw new AuthorizationDetailsProcessingException(VALIDATION_FAILED_ERR_MSG);
        }
    }

    /**
     * Checks whether the schema has a "$ref" loop that never moves deeper into the input, e.g. {"$ref": "#"}.
     * Follows "$ref" and the keywords that apply a subschema to the same input value (allOf, not, if, ...),
     * resolving each "$ref" the same way as the validator does.
     */
    private boolean hasReferenceLoop(final JsonObject jsonSchema) {

        final SchemaRepository lookup =
                SchemaRepository.create(this.jsonSchemaOptions).dereference(JsonSchema.of(jsonSchema));
        final List<Map<?, ?>> schemaObjects = new ArrayList<>();
        collectObjects(jsonSchema.getMap(), schemaObjects);

        // Depth-first search. FALSE: on the current path, TRUE: fully explored.
        final Map<Map<?, ?>, Boolean> states = new IdentityHashMap<>();
        for (final Map<?, ?> schemaObject : schemaObjects) {
            if (hasLoopFrom(schemaObject, lookup, states)) {
                return true;
            }
        }
        return false;
    }

    private static boolean hasLoopFrom(final Map<?, ?> schemaObject, final SchemaRepository lookup,
                                       final Map<Map<?, ?>, Boolean> states) {

        final Boolean state = states.get(schemaObject);
        if (state != null) {
            return !state;
        }
        states.put(schemaObject, Boolean.FALSE);
        for (final Map<?, ?> next : getInPlaceSubschemas(schemaObject, lookup)) {
            if (hasLoopFrom(next, lookup, states)) {
                return true;
            }
        }
        states.put(schemaObject, Boolean.TRUE);
        return false;
    }

    private static List<Map<?, ?>> getInPlaceSubschemas(final Map<?, ?> schemaObject, final SchemaRepository lookup) {

        final List<Map<?, ?>> subschemas = new ArrayList<>();
        final Object absoluteRef = schemaObject.get(ABSOLUTE_REF_ANNOTATION);
        if (absoluteRef instanceof String) {
            addObject(lookup.find((String) absoluteRef), subschemas);
        }
        for (final String keyword : IN_PLACE_KEYWORDS) {
            addObject(schemaObject.get(keyword), subschemas);
        }
        for (final String keyword : IN_PLACE_ARRAY_KEYWORDS) {
            for (final Object item : asList(schemaObject.get(keyword))) {
                addObject(item, subschemas);
            }
        }
        for (final String keyword : IN_PLACE_MAP_KEYWORDS) {
            final Map<?, ?> map = asMap(schemaObject.get(keyword));
            if (map != null) {
                for (final Object value : map.values()) {
                    addObject(value, subschemas);
                }
            }
        }
        return subschemas;
    }

    private static void collectObjects(final Object json, final List<Map<?, ?>> objects) {

        final Map<?, ?> map = asMap(json);
        if (map != null) {
            objects.add(map);
            for (final Object value : map.values()) {
                collectObjects(value, objects);
            }
        } else {
            for (final Object item : asList(json)) {
                collectObjects(item, objects);
            }
        }
    }

    private static void addObject(final Object json, final List<Map<?, ?>> objects) {

        final Map<?, ?> map = asMap(json);
        if (map != null) {
            objects.add(map);
        }
    }

    private static Map<?, ?> asMap(final Object json) {

        if (json instanceof JsonObject) {
            return ((JsonObject) json).getMap();
        }
        return (json instanceof Map) ? (Map<?, ?>) json : null;
    }

    private static List<?> asList(final Object json) {

        if (json instanceof JsonArray) {
            return ((JsonArray) json).getList();
        }
        return (json instanceof List) ? (List<?>) json : Collections.emptyList();
    }

    private static boolean canDereference(final JsonObject jsonSchema, final JsonObject jsonInput) {

        // Vert.x does not implement the dynamic scope of "$dynamicRef" and accepts payloads that such a schema
        // rejects. Remove this check once https://github.com/eclipse-vertx/vertx-json-schema/issues/158 is fixed in
        // the vertx-json-schema in use.
        if (containsAnyKey(jsonSchema, DYNAMIC_REF_KEYWORD)) {
            return false;
        }
        // Dereferencing adds the annotation keys to the schema objects, including the "dependentRequired" and
        // "dependencies" objects whose keys Vert.x reads as property names. An input using one of the annotation
        // keys would then fail against such a schema.
        return !(containsAnyKey(jsonSchema, PROPERTY_NAME_KEYWORDS)
                && containsAnyKey(jsonInput, DEREFERENCE_ANNOTATIONS));
    }

    private static boolean containsAnyKey(final Object json, final List<String> keys) {

        if (json instanceof JsonObject) {
            for (final Map.Entry<String, Object> entry : (JsonObject) json) {
                if (keys.contains(entry.getKey()) || containsAnyKey(entry.getValue(), keys)) {
                    return true;
                }
            }
        } else if (json instanceof JsonArray) {
            for (final Object item : (JsonArray) json) {
                if (containsAnyKey(item, keys)) {
                    return true;
                }
            }
        }
        return false;
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

        final JsonObject jsonSchema = new JsonObject(schema);
        jsonSchema.put(ADDITIONAL_PROPERTIES, false); // Ensure no unknown fields are allowed

        return this.isSchemaCompliant(jsonSchema, authorizationDetail);
    }
}
