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

package org.wso2.carbon.identity.oauth2.validators;

import org.testng.annotations.BeforeTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;

import static org.testng.Assert.assertEquals;


/**
 * Tests JDBCScopeValidator.
 */
public class JDBCScopeValidatorTest {

    private JDBCScopeValidator validator;

    @BeforeTest
    public void setUp() {
        validator = new JDBCScopeValidator();
    }

    @Test(dataProvider = "validatingDOs")
    public void testValidateScope(AccessTokenDO accessTokenDO, String scope, boolean expectedResult) throws Exception {
        boolean result = validator.validateScope(accessTokenDO, scope);
        assertEquals(result, expectedResult);
    }


    @DataProvider(name = "validatingDOs")
    public Object[][] createValidateTokenDo() {

        AccessTokenDO accessTokenDO = new AccessTokenDO();

        return new Object[][]{
                {accessTokenDO, "scope1", true}
        };
    }

}
