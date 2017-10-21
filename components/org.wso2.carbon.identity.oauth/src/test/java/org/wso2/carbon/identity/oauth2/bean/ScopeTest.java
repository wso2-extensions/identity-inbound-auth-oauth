/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wso2.carbon.identity.oauth2.bean;

import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.Arrays;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

@PrepareForTest(StringBuilder.class)
public class ScopeTest {
    private Scope scope1;
    private Scope scope2;
    private String name = "readClaims";

    private ArrayList<String> bindings = new ArrayList<>(Arrays.asList("scope1", "scope2"));

    @BeforeTest
    public void setUp() throws IllegalAccessException, InstantiationException {

        String description = "Test cases to test scope";
        scope1 = new Scope(name, description);
        scope2 = new Scope(name, description, bindings);
    }


    @Test
    public void testGetName() throws Exception {
        assertEquals(scope1.getName(),
                "readClaims", "Valid getName().");
        assertNotEquals(scope1.getName(),
                "ReadClaims", "Invalid getName().");
    }

    @Test
    public void testSetName() throws Exception {
        scope1.setName(name = "value");
        assertEquals(scope1.getName(),
                "value", "Valid getName().");
        assertNotEquals(scope1.getName(),
                "readClaims", "Invalid getName().");

    }

    @Test
    public void testGetDescription() throws Exception {
        assertEquals(scope1.getDescription(),
                "Test cases to test scope", "Valid getDescription().");
        assertNotEquals(scope1.getDescription(),
                "Test cases to testscope", "Invalid getDescription().");
    }

    @Test
    public void testSetDescription() throws Exception {
        scope1.setDescription(name = "Testing authcontext oauth scope");
        assertEquals(scope1.getDescription(),
                "Testing authcontext oauth scope", "Valid getDescription().");
        assertNotEquals(scope1.getDescription(),
                "Testing authcontextoauth scope", "Invalid getDescription().");
    }


    @Test
    public void testAddBindings() throws Exception {
        scope2.addBinding("scope3");
        assertTrue(scope2.getBindings().contains("scope3"));

    }

    @Test
    public void testAddBinding() throws Exception {
        scope2.addBindings(Arrays.asList("scope3", "scope4"));
        assertTrue(scope2.getBindings().containsAll(Arrays.asList("scope3", "scope4")));
    }

    @Test
    public void testGetBindings() throws Exception {
        assertNotNull(bindings);
        bindings.add("scope4");
        assertEquals(scope2.getBindings(), bindings, "Actual size does not match with expected one");
    }

    @Test
    public void testSetBindings() throws Exception {
        ArrayList<String> bindings2 = new ArrayList<>(Arrays.asList("scope1", "scope2", "scope3"));
        scope2.setBindings(bindings2);
        int expectedScopeSize = 3;
        assertEquals(bindings2.size(), expectedScopeSize, "Invalid Scopes size");
    }

    @Test
    public void testToString() throws Exception {
        assertNotEquals(scope2.toString(), "Scope {\n" +
                "  name: readClaims\n" +
                "  description: Test cases to test scope\n" +
                "  bindings: [scope1, scope2]\n" +
                "}");
    }

}
