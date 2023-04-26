/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com).
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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.extension.engine.impl;

import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth.extension.engine.JSEngine;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.script.ScriptException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class OpenJdkJSEngineImplTest {

    @Test
    public void testCreateEngine() throws ScriptException {

        JSEngine engine = OpenJdkJSEngineImpl.getInstance().createEngine();
        assertNotNull(engine);
    }

    @Test
    public void testAddBindings() throws ScriptException {

        JSEngine engine = OpenJdkJSEngineImpl.getInstance().createEngine();
        Map<String, Object> bindings = new HashMap<>();
        bindings.put("name", "John");
        engine.addBindings(bindings);

        String script = "var message = 'Hello ' + name;";
        engine.evalScript(script);
        String message = (String) engine.getJSObjects(new ArrayList<>(
                Collections.singletonList("message"))).get("message");
        assertEquals("Hello John", message);
    }

    @Test
    public void testInvokeFunction() throws ScriptException, NoSuchMethodException {

        JSEngine engine = OpenJdkJSEngineImpl.getInstance().createEngine();

        String script = "function add(a, b) { result = a + b; }";
        engine.evalScript(script);
        engine.invokeFunction("add", 1, 2);
        String result = engine.getJSObjects(new ArrayList<>(
                Collections.singletonList("result"))).get("result").toString();
        assertEquals("3.0", result);
    }

    @Test
    public void testGetJSObjects() throws ScriptException, NoSuchMethodException {

        JSEngine engine = OpenJdkJSEngineImpl.getInstance().createEngine();
        String script = "function getData() { " +
                "person = {name: 'John', age: 30};" +
                "}";
        engine.evalScript(script);
        engine.invokeFunction("getData");
        Map<String, Object> jsObjects = engine.getJSObjects(new ArrayList<>(
                Collections.singletonList("person")));
        assertTrue(jsObjects.containsKey("person"));
        assertEquals("John", ((Map<?, ?>) jsObjects.get("person")).get("name"));
        assertEquals(30, ((Map<?, ?>) jsObjects.get("person")).get("age"));
    }
}
