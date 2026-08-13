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

package org.wso2.carbon.identity.oauth.rar;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.vertx.core.json.JsonObject;
import org.apache.commons.lang3.StringUtils;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth.rar.core.AuthorizationDetailsSchemaValidator;
import org.wso2.carbon.identity.oauth.rar.core.AuthorizationDetailsSchemaValidatorImpl;
import org.wso2.carbon.identity.oauth.rar.exception.AuthorizationDetailsProcessingException;
import org.wso2.carbon.identity.oauth.rar.model.AuthorizationDetail;
import org.wso2.carbon.identity.oauth.rar.util.TestDAOUtils;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;
import static org.wso2.carbon.identity.oauth.rar.util.TestConstants.TEST_SCHEMA;
import static org.wso2.carbon.identity.oauth.rar.util.TestConstants.TEST_TYPE;

/**
 * Test class for {@link AuthorizationDetailsSchemaValidator}.
 */
public class AuthorizationDetailsSchemaValidatorTest {

    private AuthorizationDetailsSchemaValidator uut;

    @BeforeClass
    public void setUp() throws JsonProcessingException {

        this.uut = AuthorizationDetailsSchemaValidatorImpl.getInstance();
    }

    @Test
    public void shouldReturnTrue_whenAuthorizationDetailIsSchemaCompliant()
            throws AuthorizationDetailsProcessingException {

        AuthorizationDetail testAuthorizationDetail = new TestDAOUtils.TestAuthorizationDetail();
        testAuthorizationDetail.setType(TEST_TYPE);

        assertTrue(this.uut.isSchemaCompliant(TEST_SCHEMA, testAuthorizationDetail));
        assertTrue(this.uut.isSchemaCompliant(this.getTestSchema(), testAuthorizationDetail));
    }

    @Test
    public void shouldReturnFalse_whenSchemaIsEmpty() throws AuthorizationDetailsProcessingException {

        assertFalse(this.uut.isSchemaCompliant(StringUtils.EMPTY, new TestDAOUtils.TestAuthorizationDetail()));
        assertFalse(this.uut.isSchemaCompliant(TEST_SCHEMA, null));
        assertFalse(this.uut.isSchemaCompliant((JsonObject) null, new TestDAOUtils.TestAuthorizationDetail()));
        assertFalse(this.uut.isSchemaCompliant(new JsonObject(), null));
        assertFalse(this.uut.isSchemaCompliant((Map<String, Object>) null, new TestDAOUtils.TestAuthorizationDetail()));
        assertFalse(this.uut.isSchemaCompliant(this.getTestSchema(), null));
    }

    @Test(expectedExceptions = {AuthorizationDetailsProcessingException.class})
    public void shouldThrowAuthorizationDetailsProcessingException_whenJsonSchemaIsInvalid()
            throws AuthorizationDetailsProcessingException {

        this.uut.isSchemaCompliant("{", new TestDAOUtils.TestAuthorizationDetail());
    }

    @Test(expectedExceptions = {AuthorizationDetailsProcessingException.class})
    public void shouldThrowAuthorizationDetailsProcessingException_whenAuthorizationDetailIsNotSchemaCompliant()
            throws AuthorizationDetailsProcessingException {

        AuthorizationDetail testAuthorizationDetail = new TestDAOUtils.TestAuthorizationDetail();
        testAuthorizationDetail.setType(TEST_TYPE);
        testAuthorizationDetail.setActions(Arrays.asList("initiate", "cancel"));

        assertTrue(this.uut.isSchemaCompliant(TEST_SCHEMA, testAuthorizationDetail));
    }

    @Test
    public void shouldReturnTrue_whenMapSchemaContainsIntegralDoubleIntegerKeywords()
            throws AuthorizationDetailsProcessingException {

        TestDAOUtils.TestAuthorizationDetail testAuthorizationDetail = new TestDAOUtils.TestAuthorizationDetail();
        testAuthorizationDetail.setType(TEST_TYPE);
        testAuthorizationDetail.setName("test_name_v1");
        testAuthorizationDetail.setActions(Arrays.asList("initiate", "cancel"));

        Map<String, Object> schema = this.getTestSchemaWithDoubleIntegerKeywords();

        assertTrue(this.uut.isSchemaCompliant(schema, testAuthorizationDetail));

        Map<String, Object> actionsSchema = this.getPropertySchema(schema, "actions");
        Map<String, Object> nameSchema = this.getPropertySchema(schema, "name");
        assertTrue(actionsSchema.get("minItems") instanceof Double);
        assertTrue(actionsSchema.get("maxItems") instanceof Double);
        assertTrue(nameSchema.get("minLength") instanceof Double);
        assertTrue(nameSchema.get("maxLength") instanceof Double);
        assertEquals(actionsSchema.get("minItems"), 1.0d);
        assertEquals(actionsSchema.get("maxItems"), 3.0d);
        assertEquals(nameSchema.get("minLength"), 1.0d);
        assertEquals(nameSchema.get("maxLength"), 20.0d);
    }

    @Test(expectedExceptions = {AuthorizationDetailsProcessingException.class})
    public void shouldThrowAuthorizationDetailsProcessingException_whenMapSchemaViolatesNormalizedMaxItems()
            throws AuthorizationDetailsProcessingException {

        TestDAOUtils.TestAuthorizationDetail testAuthorizationDetail = new TestDAOUtils.TestAuthorizationDetail();
        testAuthorizationDetail.setType(TEST_TYPE);
        testAuthorizationDetail.setName("test_name_v1");
        testAuthorizationDetail.setActions(Arrays.asList("initiate", "cancel", "confirm", "revoke"));

        this.uut.isSchemaCompliant(this.getTestSchemaWithDoubleIntegerKeywords(), testAuthorizationDetail);
    }

    @Test
    public void shouldReturnTrue_whenPropertyNameMatchesIntegerSchemaKeyword()
            throws AuthorizationDetailsProcessingException {

        TestDAOUtils.TestAuthorizationDetail testAuthorizationDetail = new TestDAOUtils.TestAuthorizationDetail();
        testAuthorizationDetail.setType(TEST_TYPE);
        testAuthorizationDetail.setDetail("maxLength", Collections.singletonList("initiate"));

        assertTrue(this.uut.isSchemaCompliant(this.getTestSchemaWithKeywordNamedProperty(), testAuthorizationDetail));
    }

    @Test
    public void shouldReturnTrue_whenIntegerKeywordsAreAtBoundaryValues()
            throws AuthorizationDetailsProcessingException {

        TestDAOUtils.TestAuthorizationDetail testAuthorizationDetail = new TestDAOUtils.TestAuthorizationDetail();
        testAuthorizationDetail.setType(TEST_TYPE);
        testAuthorizationDetail.setActions(Collections.singletonList("initiate"));

        final Map<String, Object> items = new HashMap<>();
        items.put("type", "string");

        final Map<String, Object> actions = new HashMap<>();
        actions.put("type", "array");
        actions.put("items", items);
        actions.put("minItems", 0.0d);
        actions.put("maxItems", (double) Integer.MAX_VALUE);

        final Map<String, Object> type = new HashMap<>();
        type.put("type", "string");
        type.put("enum", Collections.singletonList("test_type_v1"));

        final Map<String, Object> properties = new HashMap<>();
        properties.put("type", type);
        properties.put("actions", actions);

        final Map<String, Object> schema = new HashMap<>();
        schema.put("type", "object");
        schema.put("required", Collections.singletonList("type"));
        schema.put("properties", properties);

        assertTrue(this.uut.isSchemaCompliant(schema, testAuthorizationDetail));
    }

    @Test
    public void shouldReturnTrue_whenIntegerKeywordsAreNestedInsideSchemaLists()
            throws AuthorizationDetailsProcessingException {

        TestDAOUtils.TestAuthorizationDetail testAuthorizationDetail = new TestDAOUtils.TestAuthorizationDetail();
        testAuthorizationDetail.setType(TEST_TYPE);
        testAuthorizationDetail.setName("test_name_v1");

        final Map<String, Object> minLengthConstraint = new HashMap<>();
        minLengthConstraint.put("type", "string");
        minLengthConstraint.put("minLength", 2.0d);

        final Map<String, Object> maxLengthConstraint = new HashMap<>();
        maxLengthConstraint.put("type", "string");
        maxLengthConstraint.put("maxLength", 20.0d);

        final Map<String, Object> name = new HashMap<>();
        name.put("allOf", Arrays.asList(minLengthConstraint, maxLengthConstraint));

        final Map<String, Object> type = new HashMap<>();
        type.put("type", "string");
        type.put("enum", Collections.singletonList("test_type_v1"));

        final Map<String, Object> properties = new HashMap<>();
        properties.put("type", type);
        properties.put("name", name);

        final Map<String, Object> schema = new HashMap<>();
        schema.put("type", "object");
        schema.put("required", Collections.singletonList("type"));
        schema.put("properties", properties);

        assertTrue(this.uut.isSchemaCompliant(schema, testAuthorizationDetail));
    }

    @Test
    public void shouldNotMutateCallerOwnedSchema_whenValidatingMapSchema()
            throws AuthorizationDetailsProcessingException {

        TestDAOUtils.TestAuthorizationDetail testAuthorizationDetail = new TestDAOUtils.TestAuthorizationDetail();
        testAuthorizationDetail.setType(TEST_TYPE);
        testAuthorizationDetail.setName("test_name_v1");
        testAuthorizationDetail.setActions(Arrays.asList("initiate", "cancel"));
        testAuthorizationDetail.setDetail("amount", 5);

        Map<String, Object> schema = this.getTestSchemaWithMixedNumericKeywords();

        assertTrue(this.uut.isSchemaCompliant(schema, testAuthorizationDetail));

        // The validator must not inject `additionalProperties` into the caller owned map.
        assertFalse(schema.containsKey("additionalProperties"));
        // Nested maps and nested lists must be left exactly as the caller provided them.
        assertEquals(schema, this.getTestSchemaWithMixedNumericKeywords());

        Map<String, Object> amountSchema = this.getPropertySchema(schema, "amount");
        assertTrue(amountSchema.get("minimum") instanceof Double);
        assertTrue(amountSchema.get("multipleOf") instanceof Double);
    }

    @Test(expectedExceptions = {AuthorizationDetailsProcessingException.class})
    public void shouldThrowAuthorizationDetailsProcessingException_whenSchemaIsInvalid1()
            throws AuthorizationDetailsProcessingException {

        final String invalidSchema = "{\"type\":\"object\",\"required\":[\"type\"]," +
                "\"properties\":{\"type\":{\"type\":\"string\"},\"creditorName\":\"string\"}}";

        assertTrue(this.uut.isValidSchema(TEST_SCHEMA));
        assertFalse(this.uut.isValidSchema(StringUtils.EMPTY));
        assertFalse(this.uut.isValidSchema(invalidSchema));
    }

    @Test(expectedExceptions = {AuthorizationDetailsProcessingException.class})
    public void shouldThrowAuthorizationDetailsProcessingException_whenSchemaIsInvalid2()
            throws AuthorizationDetailsProcessingException {

        final String invalidSchema = "{\"type\":\"object\",\"required\":[\"type\"]," +
                "\"properties\":[{\"type\":{\"type\":\"string\"}}]}";

        assertFalse(this.uut.isValidSchema(invalidSchema));
    }

    private Map<String, Object> getTestSchema() {
        final Map<String, Object> items = new HashMap<>();
        items.put("type", "string");
        items.put("enum", Collections.singletonList("initiate"));

        final Map<String, Object> actions = new HashMap<>();
        actions.put("type", "array");
        actions.put("items", items);

        final Map<String, Object> type = new HashMap<>();
        type.put("type", "string");
        type.put("enum", Collections.singletonList("test_type_v1"));

        final Map<String, Object> properties = new HashMap<>();
        properties.put("type", type);
        properties.put("actions", actions);

        final Map<String, Object> schema = new HashMap<>();
        schema.put("type", "object");
        schema.put("required", Collections.singletonList("type"));
        schema.put("properties", properties);
        return schema;
    }

    private Map<String, Object> getTestSchemaWithDoubleIntegerKeywords() {

        final Map<String, Object> items = new HashMap<>();
        items.put("type", "string");

        final Map<String, Object> actions = new HashMap<>();
        actions.put("type", "array");
        actions.put("items", items);
        actions.put("minItems", 1.0d);
        actions.put("maxItems", 3.0d);

        final Map<String, Object> type = new HashMap<>();
        type.put("type", "string");
        type.put("enum", Collections.singletonList("test_type_v1"));

        final Map<String, Object> name = new HashMap<>();
        name.put("type", "string");
        name.put("minLength", 1.0d);
        name.put("maxLength", 20.0d);

        final Map<String, Object> properties = new HashMap<>();
        properties.put("type", type);
        properties.put("actions", actions);
        properties.put("name", name);

        final Map<String, Object> schema = new HashMap<>();
        schema.put("type", "object");
        schema.put("required", Arrays.asList("type", "actions", "name"));
        schema.put("properties", properties);
        return schema;
    }

    private Map<String, Object> getTestSchemaWithMixedNumericKeywords() {

        final Map<String, Object> items = new HashMap<>();
        items.put("type", "string");

        final Map<String, Object> actions = new HashMap<>();
        actions.put("type", "array");
        actions.put("items", items);
        actions.put("minItems", 1.0d);
        actions.put("maxItems", 3.0d);

        final Map<String, Object> type = new HashMap<>();
        type.put("type", "string");
        type.put("enum", Collections.singletonList("test_type_v1"));

        final Map<String, Object> name = new HashMap<>();
        name.put("type", "string");
        name.put("minLength", 1.0d);
        name.put("maxLength", 20.0d);

        // `minimum` and `multipleOf` accept non integral values and must never be converted.
        final Map<String, Object> amount = new HashMap<>();
        amount.put("type", "number");
        amount.put("minimum", 1.0d);
        amount.put("multipleOf", 1.0d);

        final Map<String, Object> properties = new HashMap<>();
        properties.put("type", type);
        properties.put("actions", actions);
        properties.put("name", name);
        properties.put("amount", amount);

        final Map<String, Object> schema = new HashMap<>();
        schema.put("type", "object");
        schema.put("required", Arrays.asList("type", "actions", "name"));
        schema.put("properties", properties);
        return schema;
    }

    private Map<String, Object> getTestSchemaWithKeywordNamedProperty() {

        final Map<String, Object> type = new HashMap<>();
        type.put("type", "string");
        type.put("enum", Collections.singletonList("test_type_v1"));

        final Map<String, Object> items = new HashMap<>();
        items.put("type", "string");

        // An authorization detail property may legitimately be named after a schema keyword.
        final Map<String, Object> keywordNamedProperty = new HashMap<>();
        keywordNamedProperty.put("type", "array");
        keywordNamedProperty.put("items", items);
        keywordNamedProperty.put("minItems", 1.0d);
        keywordNamedProperty.put("maxItems", 3.0d);

        final Map<String, Object> properties = new HashMap<>();
        properties.put("type", type);
        properties.put("maxLength", keywordNamedProperty);

        final Map<String, Object> schema = new HashMap<>();
        schema.put("type", "object");
        schema.put("required", Collections.singletonList("type"));
        schema.put("properties", properties);
        return schema;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> getPropertySchema(final Map<String, Object> schema, final String propertyName) {

        return (Map<String, Object>) ((Map<String, Object>) schema.get("properties")).get(propertyName);
    }
}
