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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
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
}
