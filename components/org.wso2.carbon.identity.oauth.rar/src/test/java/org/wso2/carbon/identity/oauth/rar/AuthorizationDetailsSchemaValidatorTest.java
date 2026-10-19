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
import io.vertx.json.schema.SchemaException;
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

import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;
import static org.wso2.carbon.identity.oauth.rar.util.TestConstants.TEST_SCHEMA;
import static org.wso2.carbon.identity.oauth.rar.util.TestConstants.TEST_SCHEMA_WITH_DEFS;
import static org.wso2.carbon.identity.oauth.rar.util.TestConstants.TEST_SCHEMA_WITH_DEPENDENT_REQUIRED;
import static org.wso2.carbon.identity.oauth.rar.util.TestConstants.TEST_SCHEMA_WITH_DUPLICATE_ID;
import static org.wso2.carbon.identity.oauth.rar.util.TestConstants.TEST_SCHEMA_WITH_DYNAMIC_REF;
import static org.wso2.carbon.identity.oauth.rar.util.TestConstants.TEST_SCHEMA_WITH_RECURSION;
import static org.wso2.carbon.identity.oauth.rar.util.TestConstants.TEST_SCHEMA_WITH_REFERENCE_LOOP;
import static org.wso2.carbon.identity.oauth.rar.util.TestConstants.TEST_SCHEMA_WITH_REF_IN_DEPENDENT_REQUIRED;
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
    public void shouldReturnTrue_whenAuthorizationDetailIsCompliantWithSchemaUsingDefs()
            throws AuthorizationDetailsProcessingException {

        AuthorizationDetail testAuthorizationDetail = new TestDAOUtils.TestAuthorizationDetail();
        testAuthorizationDetail.setType(TEST_TYPE);
        testAuthorizationDetail.setActions(Collections.singletonList("initiate"));

        assertTrue(this.uut.isSchemaCompliant(TEST_SCHEMA_WITH_DEFS, testAuthorizationDetail));
        assertTrue(this.uut.isSchemaCompliant(new JsonObject(TEST_SCHEMA_WITH_DEFS).getMap(),
                testAuthorizationDetail));
    }

    @Test(expectedExceptions = {AuthorizationDetailsProcessingException.class})
    public void shouldThrowAuthorizationDetailsProcessingException_whenAuthorizationDetailViolatesDefs()
            throws AuthorizationDetailsProcessingException {

        AuthorizationDetail testAuthorizationDetail = new TestDAOUtils.TestAuthorizationDetail();
        testAuthorizationDetail.setType(TEST_TYPE);
        testAuthorizationDetail.setActions(Collections.singletonList("cancel"));

        this.uut.isSchemaCompliant(new JsonObject(TEST_SCHEMA_WITH_DEFS).getMap(), testAuthorizationDetail);
    }

    @Test
    public void shouldReturnTrue_whenSchemaCannotBeDereferencedAndAuthorizationDetailIsSchemaCompliant()
            throws AuthorizationDetailsProcessingException {

        AuthorizationDetail testAuthorizationDetail = new TestDAOUtils.TestAuthorizationDetail();
        testAuthorizationDetail.setType(TEST_TYPE);
        testAuthorizationDetail.setActions(Collections.singletonList("initiate"));

        assertTrue(this.uut.isSchemaCompliant(TEST_SCHEMA_WITH_DUPLICATE_ID, testAuthorizationDetail));
        assertTrue(this.uut.isSchemaCompliant(new JsonObject(TEST_SCHEMA_WITH_DUPLICATE_ID).getMap(),
                testAuthorizationDetail));
    }

    @Test(expectedExceptions = {AuthorizationDetailsProcessingException.class})
    public void shouldThrowAuthorizationDetailsProcessingException_whenSchemaCannotBeDereferencedAndIsViolated()
            throws AuthorizationDetailsProcessingException {

        AuthorizationDetail testAuthorizationDetail = new TestDAOUtils.TestAuthorizationDetail();
        testAuthorizationDetail.setType(TEST_TYPE);
        testAuthorizationDetail.setActions(Collections.singletonList("cancel"));

        this.uut.isSchemaCompliant(TEST_SCHEMA_WITH_DUPLICATE_ID, testAuthorizationDetail);
    }

    @Test
    public void shouldReturnTrue_whenAuthorizationDetailUsesDereferenceAnnotationKey()
            throws AuthorizationDetailsProcessingException {

        AuthorizationDetail testAuthorizationDetail = new TestDAOUtils.TestAuthorizationDetail();
        testAuthorizationDetail.setType(TEST_TYPE);
        testAuthorizationDetail.setDetail("__absolute_uri__", "test_value");

        assertTrue(this.uut.isSchemaCompliant(TEST_SCHEMA_WITH_DEPENDENT_REQUIRED, testAuthorizationDetail));
        assertTrue(this.uut.isSchemaCompliant(new JsonObject(TEST_SCHEMA_WITH_DEPENDENT_REQUIRED).getMap(),
                testAuthorizationDetail));
    }

    @Test
    public void shouldReturnTrue_whenSchemaUsingDefsReceivesDereferenceAnnotationKey()
            throws AuthorizationDetailsProcessingException {

        AuthorizationDetail testAuthorizationDetail = new TestDAOUtils.TestAuthorizationDetail();
        testAuthorizationDetail.setType(TEST_TYPE);
        testAuthorizationDetail.setActions(Collections.singletonList("initiate"));
        testAuthorizationDetail.setDetail("__absolute_uri__", "test_value");

        assertTrue(this.uut.isSchemaCompliant(TEST_SCHEMA_WITH_DEFS, testAuthorizationDetail));
    }

    @Test
    public void shouldReturnTrue_whenSchemaDereferencingFailsWithUnexpectedError()
            throws AuthorizationDetailsProcessingException {

        AuthorizationDetail testAuthorizationDetail = new TestDAOUtils.TestAuthorizationDetail();
        testAuthorizationDetail.setType(TEST_TYPE);

        assertTrue(this.uut.isSchemaCompliant(TEST_SCHEMA_WITH_REF_IN_DEPENDENT_REQUIRED, testAuthorizationDetail));
        assertTrue(this.uut.isSchemaCompliant(new JsonObject(TEST_SCHEMA_WITH_REF_IN_DEPENDENT_REQUIRED).getMap(),
                testAuthorizationDetail));
    }

    @Test(expectedExceptions = {SchemaException.class},
            expectedExceptionsMessageRegExp = "(?s)Unresolved \\$ref item.*")
    public void shouldValidateWithoutDereferencing_whenSchemaUsesDynamicRef()
            throws AuthorizationDetailsProcessingException {

        AuthorizationDetail testAuthorizationDetail = new TestDAOUtils.TestAuthorizationDetail();
        testAuthorizationDetail.setType(TEST_TYPE);
        testAuthorizationDetail.setDetail("bar-item", Collections.singletonMap("content", "test_value"));

        // Without dereferencing, the schema's "$ref" to "item" is unresolved. With dereferencing, Vert.x would
        // accept this authorization detail although "content" must be an integer.
        this.uut.isSchemaCompliant(TEST_SCHEMA_WITH_DYNAMIC_REF, testAuthorizationDetail);
    }

    @Test(expectedExceptions = {SchemaException.class},
            expectedExceptionsMessageRegExp = "(?s)Unresolved \\$ref #/\\$defs/a.*")
    public void shouldValidateWithoutDereferencing_whenSchemaHasReferenceLoop()
            throws AuthorizationDetailsProcessingException {

        AuthorizationDetail testAuthorizationDetail = new TestDAOUtils.TestAuthorizationDetail();
        testAuthorizationDetail.setType(TEST_TYPE);

        // Without dereferencing, the "$ref" is unresolved, as before. With dereferencing, Vert.x would follow the
        // loop until the stack overflows.
        this.uut.isSchemaCompliant(TEST_SCHEMA_WITH_REFERENCE_LOOP, testAuthorizationDetail);
    }

    @Test
    public void shouldReturnTrue_whenRecursiveSchemaReceivesNestedAuthorizationDetail()
            throws AuthorizationDetailsProcessingException {

        AuthorizationDetail testAuthorizationDetail = new TestDAOUtils.TestAuthorizationDetail();
        testAuthorizationDetail.setType(TEST_TYPE);
        testAuthorizationDetail.setDetail("child", nestedChildren(5));

        assertTrue(this.uut.isSchemaCompliant(TEST_SCHEMA_WITH_RECURSION, testAuthorizationDetail));
    }

    @Test
    public void shouldThrowAuthorizationDetailsProcessingException_whenInputIsNestedTooDeeplyForRecursiveSchema()
            throws InterruptedException {

        AuthorizationDetail testAuthorizationDetail = new TestDAOUtils.TestAuthorizationDetail();
        testAuthorizationDetail.setType(TEST_TYPE);
        testAuthorizationDetail.setDetail("child", nestedChildren(500));

        // Validate on a thread with a small stack, so that the recursion exhausts it.
        final Throwable[] thrown = new Throwable[1];
        final Thread thread = new Thread(null, () -> {
            try {
                this.uut.isSchemaCompliant(TEST_SCHEMA_WITH_RECURSION, testAuthorizationDetail);
            } catch (Throwable t) {
                thrown[0] = t;
            }
        }, "deep-input-validation", 512 * 1024);
        thread.start();
        thread.join();

        assertTrue(thrown[0] instanceof AuthorizationDetailsProcessingException, String.valueOf(thrown[0]));
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

    private Map<String, Object> nestedChildren(final int depth) {

        Map<String, Object> child = new HashMap<>();
        for (int i = 1; i < depth; i++) {
            child = Collections.singletonMap("child", child);
        }
        return child;
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
}
