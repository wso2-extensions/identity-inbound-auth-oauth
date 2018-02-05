/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.token.handlers.grant;

import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.AfterTest;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.testng.AssertJUnit.assertEquals;

/**
 * This class defines unit test for AbstractValidator class
 */
public class AbstractValidatorTest extends PowerMockTestCase {

    AbstractValidator abstractValidator;
    private static final String KEY   = "key";
    private static final String VALUE = "value";
    private static final String NOT_ALLOWED_PARAM = "notAllowedParam";

    @BeforeTest
    public void setUp() {

        abstractValidator = new AbstractValidator() {
            @Override
            protected void configureParams() {
                this.requiredParams = null;
            }
        };
    }

    @AfterTest
    public void cleanUp() {

        abstractValidator = null;
    }

    @Test
    public void testGetRequiredParams() {

        ArrayList<String> params = new ArrayList<>();
        abstractValidator.setRequiredParams(params);
        assertTrue(params.equals(abstractValidator.getRequiredParams()));
    }

    @Test
    public void testSetRequiredParams() {

        List<String> requiredParams = new ArrayList<>();
        abstractValidator.setRequiredParams(requiredParams);
        assertEquals(abstractValidator.getRequiredParams(), requiredParams);
    }

    @Test
    public void testAddRequiredParam() {

        String param = "param";
        abstractValidator.setRequiredParams(new ArrayList<String>());
        abstractValidator.addRequiredParam(param);
        assertTrue(abstractValidator.getRequiredParams().contains(param));
    }

    @Test
    public void testRemoveRequiredParam() {

        String param = "param1";
        abstractValidator.addRequiredParam(param);
        abstractValidator.removeRequiredParam(param);
        assertFalse(abstractValidator.getRequiredParams().contains(param));
    }

    @Test
    public void testGetAndSetOptionalParams() {

        Map<String, String> optionalParams = new HashMap<>();
        abstractValidator.setOptionalParams(optionalParams);
        assertEquals(abstractValidator.getOptionalParams(), optionalParams);
    }

    @Test
    public void testAddOptionalParams() {

        abstractValidator.addOptionalParam(KEY, VALUE);
        assertTrue(abstractValidator.getOptionalParams().containsKey(KEY));
        assertEquals(abstractValidator.getOptionalParams().get(KEY), VALUE);
    }

    @Test
    public void testRemoveOptionalParam() {

        abstractValidator.addOptionalParam(KEY, VALUE);
        abstractValidator.removeOptionalParam(KEY);
        assertFalse(abstractValidator.getOptionalParams().containsKey(KEY));
    }

    @Test
    public void testGetAndSetNotAllowedParamsParams() {

        List<String> notAllowedParams = new ArrayList<>();
        abstractValidator.setNotAllowedParamsParams(notAllowedParams);
        assertEquals(abstractValidator.getNotAllowedParamsParams(), notAllowedParams);

        abstractValidator.setNotAllowedParamsParams(null);
        assertNotNull(abstractValidator.getNotAllowedParamsParams());
    }

    @Test
    public void testAddNotAllowedParamsParam() {


        abstractValidator.setNotAllowedParamsParams(new ArrayList<String>());
        abstractValidator.addNotAllowedParamsParam(NOT_ALLOWED_PARAM);
        assertTrue(abstractValidator.getNotAllowedParamsParams().contains(NOT_ALLOWED_PARAM));
    }

    @Test
    public void testRemoveNotAllowedParamsParam() {

        abstractValidator.setNotAllowedParamsParams(new ArrayList<String>());
        abstractValidator.addNotAllowedParamsParam(NOT_ALLOWED_PARAM);
        abstractValidator.removeNotAllowedParamsParam(NOT_ALLOWED_PARAM);
        assertFalse(abstractValidator.getNotAllowedParamsParams().contains(NOT_ALLOWED_PARAM));
    }

    @Test
    public void testSetEnforceClientAuthentication() {
        assertFalse(abstractValidator.isEnforceClientAuthentication());

        abstractValidator.setEnforceClientAuthentication(true);
        assertTrue(abstractValidator.isEnforceClientAuthentication());
    }


}
