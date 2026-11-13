/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.json.schema.SchemaRepository;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;

/**
 * Utility methods for walking the JSON schemas of authorization details types.
 */
public final class AuthorizationDetailsSchemaUtils {

    public static final String REF_KEYWORD = "$ref";
    public static final String DYNAMIC_REF_KEYWORD = "$dynamicRef";
    public static final String ABSOLUTE_REF_ANNOTATION = "__absolute_ref__";
    // Keys that Vert.x adds to the schema objects when it dereferences a schema.
    public static final List<String> DEREFERENCE_ANNOTATIONS = Collections.unmodifiableList(
            Arrays.asList("__absolute_uri__", ABSOLUTE_REF_ANNOTATION, "__absolute_recursive_ref__"));

    // Keywords whose subschemas are applied to the same input location as the schema that holds them.
    private static final List<String> IN_PLACE_KEYWORDS = Arrays.asList("not", "if", "then", "else");
    private static final List<String> IN_PLACE_ARRAY_KEYWORDS = Arrays.asList("allOf", "anyOf", "oneOf");
    private static final List<String> IN_PLACE_MAP_KEYWORDS = Arrays.asList("dependentSchemas", "dependencies");
    // Keywords whose values are subschemas: one subschema, an array of subschemas, or a map of subschemas.
    private static final List<String> SUBSCHEMA_KEYWORDS = Arrays.asList("additionalItems", "unevaluatedItems",
            "items", "contains", "additionalProperties", "unevaluatedProperties", "propertyNames", "not", "if",
            "then", "else");
    private static final List<String> SUBSCHEMA_ARRAY_KEYWORDS =
            Arrays.asList("prefixItems", "items", "allOf", "anyOf", "oneOf");
    private static final List<String> SUBSCHEMA_MAP_KEYWORDS = Arrays.asList("$defs", "definitions", "properties",
            "patternProperties", "dependentSchemas", "dependencies");
    // Keywords whose values hold property names: a map keyed by property name, or an array of property names.
    private static final List<String> PROPERTY_NAME_MAP_KEYWORDS =
            Arrays.asList("properties", "dependentRequired", "dependencies");
    private static final List<String> PROPERTY_NAME_ARRAY_KEYWORDS = Collections.singletonList("required");

    private AuthorizationDetailsSchemaUtils() {
        // Private constructor to prevent instantiation
    }

    /**
     * Returns the schema and every subschema in it, visiting only the keywords that hold subschemas.
     *
     * @param schema the schema.
     * @return the schema followed by its subschemas.
     */
    public static List<Map<?, ?>> collectSubschemas(final Map<?, ?> schema) {

        final List<Map<?, ?>> subschemas = new ArrayList<>();
        collectSubschemas(schema, subschemas);
        return subschemas;
    }

    /**
     * Returns the first dereference annotation key that the given subschemas use, as a keyword or as a property
     * name, or null if they use none.
     *
     * @param subschemas the subschemas returned by {@link #collectSubschemas(Map)}.
     * @return the annotation key, or null.
     */
    public static String findDereferenceAnnotation(final List<Map<?, ?>> subschemas) {

        for (final Map<?, ?> subschema : subschemas) {
            final List<Object> names = new ArrayList<>(subschema.keySet());
            for (final String keyword : PROPERTY_NAME_MAP_KEYWORDS) {
                final Map<?, ?> map = asMap(subschema.get(keyword));
                if (map != null) {
                    names.addAll(map.keySet());
                    for (final Object value : map.values()) {
                        names.addAll(asList(value));
                    }
                }
            }
            for (final String keyword : PROPERTY_NAME_ARRAY_KEYWORDS) {
                names.addAll(asList(subschema.get(keyword)));
            }
            for (final String annotation : DEREFERENCE_ANNOTATIONS) {
                if (names.contains(annotation)) {
                    return annotation;
                }
            }
        }
        return null;
    }

    /**
     * Checks whether the schema has a "$ref" loop that never moves deeper into the input, e.g. {"$ref": "#"}.
     * Follows "$ref" and the keywords that apply a subschema to the same input value (allOf, not, if, ...),
     * resolving each "$ref" the same way as the validator does.
     *
     * @param jsonSchema the schema, after it is dereferenced into the lookup.
     * @param lookup     a Vert.x repository that the schema is dereferenced into.
     * @return true if the schema has such a loop.
     */
    public static boolean hasReferenceLoop(final JsonObject jsonSchema, final SchemaRepository lookup) {

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

    /**
     * Checks whether the JSON value has an object key, at any depth, that is one of the given keys.
     *
     * @param json the JSON value.
     * @param keys the keys to look for.
     * @return true if one of the keys is found.
     */
    public static boolean containsAnyKey(final Object json, final List<String> keys) {

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

    private static void collectSubschemas(final Map<?, ?> schema, final List<Map<?, ?>> subschemas) {

        subschemas.add(schema);
        for (final Map.Entry<?, ?> entry : schema.entrySet()) {
            final Object keyword = entry.getKey();
            final Map<?, ?> map = asMap(entry.getValue());
            if (map != null && SUBSCHEMA_KEYWORDS.contains(keyword)) {
                collectSubschemas(map, subschemas);
            } else if (map != null && SUBSCHEMA_MAP_KEYWORDS.contains(keyword)) {
                for (final Object value : map.values()) {
                    final Map<?, ?> subschema = asMap(value);
                    if (subschema != null) {
                        collectSubschemas(subschema, subschemas);
                    }
                }
            } else if (SUBSCHEMA_ARRAY_KEYWORDS.contains(keyword)) {
                for (final Object item : asList(entry.getValue())) {
                    final Map<?, ?> subschema = asMap(item);
                    if (subschema != null) {
                        collectSubschemas(subschema, subschemas);
                    }
                }
            }
        }
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
}
