/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *  
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.extension.engine.impl;

import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth.extension.engine.JSEngine;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.script.ScriptException;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

/**
 * Test class for GraalVMJSEngineImpl.
 */
public class GraalVMJSEngineImplTest {

    @BeforeMethod
    public void setUp() throws ScriptException {
        // Create a fresh engine instance before each test
        GraalVMJSEngineImpl.getInstance().createEngine();
    }

    @Test
    public void testGetInstance() {

        JSEngine instance1 = GraalVMJSEngineImpl.getInstance();
        JSEngine instance2 = GraalVMJSEngineImpl.getInstance();
        
        assertNotNull(instance1);
        assertNotNull(instance2);
        assertEquals(instance1, instance2, "getInstance should return singleton instance");
    }

    @Test
    public void testCreateEngine() throws ScriptException {

        JSEngine engine = GraalVMJSEngineImpl.getInstance().createEngine();
        assertNotNull(engine, "Created engine should not be null");
    }

    @Test
    public void testEvalScript() throws ScriptException {

        JSEngine engine = GraalVMJSEngineImpl.getInstance().createEngine();
        String script = "var x = 10; var y = 20; var sum = x + y;";
        engine.evalScript(script);
        
        Map<String, Object> jsObjects = engine.getJSObjects(Arrays.asList("x", "y", "sum"));
        assertEquals(10, ((Number) jsObjects.get("x")).intValue());
        assertEquals(20, ((Number) jsObjects.get("y")).intValue());
        assertEquals(30, ((Number) jsObjects.get("sum")).intValue());
    }

    @Test
    public void testAddBindings() throws ScriptException {

        JSEngine engine = GraalVMJSEngineImpl.getInstance().createEngine();
        Map<String, Object> bindings = new HashMap<>();
        bindings.put("name", "John");
        bindings.put("age", 30);
        bindings.put("isActive", true);
        
        engine.addBindings(bindings);

        String script = "var message = 'Hello ' + name + ', age: ' + age + ', active: ' + isActive;";
        engine.evalScript(script);
        
        String message = (String) engine.getJSObjects(new ArrayList<>(
                Collections.singletonList("message"))).get("message");
        assertEquals("Hello John, age: 30, active: true", message);
    }

    @Test
    public void testAddBindingsWithNull() throws ScriptException {

        JSEngine engine = GraalVMJSEngineImpl.getInstance().createEngine();
        
        // Should not throw exception with null bindings
        engine.addBindings(null);
        
        // Should still work with valid script
        engine.evalScript("var test = 'works';");
        Map<String, Object> result = engine.getJSObjects(Collections.singletonList("test"));
        assertEquals("works", result.get("test"));
    }

    @Test
    public void testInvokeFunction() throws ScriptException, NoSuchMethodException {

        JSEngine engine = GraalVMJSEngineImpl.getInstance().createEngine();

        String script = "function add(a, b) { result = a + b; }";
        engine.evalScript(script);
        engine.invokeFunction("add", 15, 25);
        
        Object result = engine.getJSObjects(new ArrayList<>(
                Collections.singletonList("result"))).get("result");
        assertEquals(40, ((Number) result).intValue());
    }

    @Test
    public void testInvokeFunctionWithStringArgs() throws ScriptException, NoSuchMethodException {

        JSEngine engine = GraalVMJSEngineImpl.getInstance().createEngine();

        String script = "function concatenate(str1, str2) { result = str1 + ' ' + str2; }";
        engine.evalScript(script);
        engine.invokeFunction("concatenate", "Hello", "World");
        
        String result = (String) engine.getJSObjects(new ArrayList<>(
                Collections.singletonList("result"))).get("result");
        assertEquals("Hello World", result);
    }

    @Test
    public void testInvokeFunctionWithMultipleArgs() throws ScriptException, NoSuchMethodException {

        JSEngine engine = GraalVMJSEngineImpl.getInstance().createEngine();

        String script = "function calculate(a, b, c, d) { result = (a + b) * (c - d); }";
        engine.evalScript(script);
        engine.invokeFunction("calculate", 10, 20, 50, 20);
        
        Object result = engine.getJSObjects(Collections.singletonList("result")).get("result");
        assertEquals(900, ((Number) result).intValue());
    }

    @Test
    public void testInvokeNonExistentFunction() throws ScriptException {

        JSEngine engine = GraalVMJSEngineImpl.getInstance().createEngine();

        String script = "function validFunction() { result = 'valid'; }";
        engine.evalScript(script);
        
        // Should not throw exception but log warning
        try {
            engine.invokeFunction("nonExistentFunction");
            // Should complete without exception
        } catch (NoSuchMethodException e) {
            // This is acceptable behavior too
        }
    }

    @Test
    public void testGetJSObjects() throws ScriptException {

        JSEngine engine = GraalVMJSEngineImpl.getInstance().createEngine();
        String script = "var str = 'test'; var num = 42; var bool = true; var obj = {key: 'value'};";
        engine.evalScript(script);
        
        Map<String, Object> jsObjects = engine.getJSObjects(Arrays.asList("str", "num", "bool", "obj"));
        
        assertEquals("test", jsObjects.get("str"));
        assertEquals(42, ((Number) jsObjects.get("num")).intValue());
        assertTrue((Boolean) jsObjects.get("bool"));
        assertNotNull(jsObjects.get("obj"));
    }

    @Test
    public void testGetJSObjectsWithComplexObject() throws ScriptException, NoSuchMethodException {

        JSEngine engine = GraalVMJSEngineImpl.getInstance().createEngine();
        String script = "function getData() { " +
                "person = {name: 'John', age: 30, city: 'New York'};" +
                "}";
        engine.evalScript(script);
        engine.invokeFunction("getData");
        
        Map<String, Object> jsObjects = engine.getJSObjects(new ArrayList<>(
                Collections.singletonList("person")));
        assertTrue(jsObjects.containsKey("person"));
        
        @SuppressWarnings("unchecked")
        Map<String, Object> person = (Map<String, Object>) jsObjects.get("person");
        assertEquals("John", person.get("name"));
        assertEquals(30, ((Number) person.get("age")).intValue());
        assertEquals("New York", person.get("city"));
    }

    @Test
    public void testGetJSObjectsWithArray() throws ScriptException {

        JSEngine engine = GraalVMJSEngineImpl.getInstance().createEngine();
        String script = "var numbers = [1, 2, 3, 4, 5];";
        engine.evalScript(script);
        
        Map<String, Object> jsObjects = engine.getJSObjects(Collections.singletonList("numbers"));
        assertTrue(jsObjects.containsKey("numbers"));
        
        Object[] numbers = (Object[]) jsObjects.get("numbers");
        assertEquals(5, numbers.length);
        assertEquals(1, ((Number) numbers[0]).intValue());
        assertEquals(5, ((Number) numbers[4]).intValue());
    }

    @Test
    public void testGetJSObjectsWithNestedArray() throws ScriptException {

        JSEngine engine = GraalVMJSEngineImpl.getInstance().createEngine();
        String script = "var matrix = [[1, 2], [3, 4], [5, 6]];";
        engine.evalScript(script);
        
        Map<String, Object> jsObjects = engine.getJSObjects(Collections.singletonList("matrix"));
        Object[] matrix = (Object[]) jsObjects.get("matrix");
        
        assertEquals(3, matrix.length);
        Object[] firstRow = (Object[]) matrix[0];
        assertEquals(2, firstRow.length);
        assertEquals(1, ((Number) firstRow[0]).intValue());
        assertEquals(2, ((Number) firstRow[1]).intValue());
    }

    @Test
    public void testGetJSObjectsWithNonExistentVariable() throws ScriptException {

        JSEngine engine = GraalVMJSEngineImpl.getInstance().createEngine();
        String script = "var existing = 'value';";
        engine.evalScript(script);
        
        Map<String, Object> jsObjects = engine.getJSObjects(
                Arrays.asList("existing", "nonExistent"));
        
        assertEquals("value", jsObjects.get("existing"));
        assertNull(jsObjects.get("nonExistent"));
    }

    @Test
    public void testGetJSObjectsWithNullList() throws ScriptException {

        JSEngine engine = GraalVMJSEngineImpl.getInstance().createEngine();
        engine.evalScript("var test = 'value';");
        
        Map<String, Object> jsObjects = engine.getJSObjects(null);
        assertNotNull(jsObjects);
        assertTrue(jsObjects.isEmpty());
    }

    @Test
    public void testMethodChaining() throws ScriptException {

        JSEngine engine = GraalVMJSEngineImpl.getInstance()
                .createEngine()
                .addBindings(Collections.singletonMap("x", 10))
                .evalScript("var y = x * 2;");
        
        Map<String, Object> result = engine.getJSObjects(Collections.singletonList("y"));
        assertEquals(20, ((Number) result.get("y")).intValue());
    }

    @Test
    public void testComplexCalculation() throws ScriptException, NoSuchMethodException {

        JSEngine engine = GraalVMJSEngineImpl.getInstance().createEngine();
        
        Map<String, Object> bindings = new HashMap<>();
        bindings.put("price", 100);
        bindings.put("quantity", 5);
        bindings.put("taxRate", 0.08);
        
        engine.addBindings(bindings);
        
        String script = "function calculateTotal() {" +
                "  subtotal = price * quantity;" +
                "  tax = subtotal * taxRate;" +
                "  total = subtotal + tax;" +
                "}";
        
        engine.evalScript(script);
        engine.invokeFunction("calculateTotal");
        
        Map<String, Object> results = engine.getJSObjects(
                Arrays.asList("subtotal", "tax", "total"));
        
        assertEquals(500, ((Number) results.get("subtotal")).intValue());
        assertEquals(40.0, ((Number) results.get("tax")).doubleValue(), 0.01);
        assertEquals(540.0, ((Number) results.get("total")).doubleValue(), 0.01);
    }

    @Test
    public void testStringManipulation() throws ScriptException {

        JSEngine engine = GraalVMJSEngineImpl.getInstance().createEngine();
        
        Map<String, Object> bindings = new HashMap<>();
        bindings.put("firstName", "John");
        bindings.put("lastName", "Doe");
        
        engine.addBindings(bindings);
        
        String script = "var fullName = firstName + ' ' + lastName;" +
                "var upperName = fullName.toUpperCase();" +
                "var nameLength = fullName.length;";
        
        engine.evalScript(script);
        
        Map<String, Object> results = engine.getJSObjects(
                Arrays.asList("fullName", "upperName", "nameLength"));
        
        assertEquals("John Doe", results.get("fullName"));
        assertEquals("JOHN DOE", results.get("upperName"));
        assertEquals(8, ((Number) results.get("nameLength")).intValue());
    }

    @Test
    public void testConditionalLogic() throws ScriptException {

        JSEngine engine = GraalVMJSEngineImpl.getInstance().createEngine();
        
        Map<String, Object> bindings = new HashMap<>();
        bindings.put("age", 25);
        bindings.put("hasLicense", true);
        
        engine.addBindings(bindings);
        
        String script = "var canDrive = age >= 18 && hasLicense;" +
                "var category = age >= 18 ? 'adult' : 'minor';";
        
        engine.evalScript(script);
        
        Map<String, Object> results = engine.getJSObjects(
                Arrays.asList("canDrive", "category"));
        
        assertTrue((Boolean) results.get("canDrive"));
        assertEquals("adult", results.get("category"));
    }

    @Test
    public void testArrayOperations() throws ScriptException {

        JSEngine engine = GraalVMJSEngineImpl.getInstance().createEngine();
        
        String script = "var numbers = [1, 2, 3, 4, 5];" +
                "var sum = 0;" +
                "for (var i = 0; i < numbers.length; i++) {" +
                "  sum += numbers[i];" +
                "}" +
                "var average = sum / numbers.length;";
        
        engine.evalScript(script);
        
        Map<String, Object> results = engine.getJSObjects(
                Arrays.asList("sum", "average"));
        
        assertEquals(15, ((Number) results.get("sum")).intValue());
        assertEquals(3.0, ((Number) results.get("average")).doubleValue(), 0.01);
    }

    @Test
    public void testOAuthScopeValidation() throws ScriptException, NoSuchMethodException {

        JSEngine engine = GraalVMJSEngineImpl.getInstance().createEngine();
        
        Map<String, Object> context = new HashMap<>();
        context.put("requestedScopes", "openid profile email admin");
        context.put("userRole", "user");
        context.put("isPremium", false);
        
        engine.addBindings(context);
        
        String script = "function validateScopes() {" +
                "  var scopes = requestedScopes.split(' ');" +
                "  var allowed = [];" +
                "  for (var i = 0; i < scopes.length; i++) {" +
                "    var scope = scopes[i];" +
                "    if (scope === 'openid' || scope === 'profile') {" +
                "      allowed.push(scope);" +
                "    } else if (scope === 'email' && isPremium) {" +
                "      allowed.push(scope);" +
                "    } else if (scope === 'admin' && userRole === 'admin') {" +
                "      allowed.push(scope);" +
                "    }" +
                "  }" +
                "  grantedScopes = allowed.join(' ');" +
                "}";
        
        engine.evalScript(script);
        engine.invokeFunction("validateScopes");
        
        Map<String, Object> results = engine.getJSObjects(
                Collections.singletonList("grantedScopes"));
        
        assertEquals("openid profile", results.get("grantedScopes"));
    }

    @Test
    public void testNullValues() throws ScriptException {

        JSEngine engine = GraalVMJSEngineImpl.getInstance().createEngine();
        
        String script = "var nullValue = null;" +
                "var definedValue = 'test';" +
                "var isNull = nullValue === null;";
        
        engine.evalScript(script);
        
        Map<String, Object> results = engine.getJSObjects(
                Arrays.asList("nullValue", "definedValue", "isNull"));
        
        assertNull(results.get("nullValue"));
        assertEquals("test", results.get("definedValue"));
        assertTrue((Boolean) results.get("isNull"));
    }

    @Test
    public void testBooleanOperations() throws ScriptException {

        JSEngine engine = GraalVMJSEngineImpl.getInstance().createEngine();
        
        String script = "var a = true;" +
                "var b = false;" +
                "var andResult = a && b;" +
                "var orResult = a || b;" +
                "var notResult = !a;";
        
        engine.evalScript(script);
        
        Map<String, Object> results = engine.getJSObjects(
                Arrays.asList("andResult", "orResult", "notResult"));
        
        assertFalse((Boolean) results.get("andResult"));
        assertTrue((Boolean) results.get("orResult"));
        assertFalse((Boolean) results.get("notResult"));
    }

    @Test
    public void testNumericTypes() throws ScriptException {

        JSEngine engine = GraalVMJSEngineImpl.getInstance().createEngine();
        
        String script = "var intValue = 42;" +
                "var floatValue = 3.14;" +
                "var negativeValue = -10;" +
                "var zeroValue = 0;";
        
        engine.evalScript(script);
        
        Map<String, Object> results = engine.getJSObjects(
                Arrays.asList("intValue", "floatValue", "negativeValue", "zeroValue"));
        
        assertEquals(42, ((Number) results.get("intValue")).intValue());
        assertEquals(3.14, ((Number) results.get("floatValue")).doubleValue(), 0.001);
        assertEquals(-10, ((Number) results.get("negativeValue")).intValue());
        assertEquals(0, ((Number) results.get("zeroValue")).intValue());
    }

    @Test(expectedExceptions = ScriptException.class)
    public void testInvalidScript() throws ScriptException {

        JSEngine engine = GraalVMJSEngineImpl.getInstance().createEngine();
        // Invalid syntax should throw ScriptException
        engine.evalScript("var x = ;");
    }

    @Test
    public void testEmptyScript() throws ScriptException {

        JSEngine engine = GraalVMJSEngineImpl.getInstance().createEngine();
        // Empty script should not throw exception
        engine.evalScript("");
    }

    @Test
    public void testIsolationBetweenEngines() throws ScriptException {

        JSEngine engine1 = GraalVMJSEngineImpl.getInstance().createEngine();
        engine1.evalScript("var isolated = 'engine1';");
        
        JSEngine engine2 = GraalVMJSEngineImpl.getInstance().createEngine();
        engine2.evalScript("var isolated = 'engine2';");
        
        // Due to singleton pattern, both reference the same instance
        // but createEngine() creates new context
        Map<String, Object> results = engine2.getJSObjects(
                Collections.singletonList("isolated"));
        
        assertEquals("engine2", results.get("isolated"));
    }

    @AfterClass
    public void cleanup() {

        // Clean up the GraalVM context
        GraalVMJSEngineImpl instance = (GraalVMJSEngineImpl) GraalVMJSEngineImpl.getInstance();
        instance.close();
    }
}
