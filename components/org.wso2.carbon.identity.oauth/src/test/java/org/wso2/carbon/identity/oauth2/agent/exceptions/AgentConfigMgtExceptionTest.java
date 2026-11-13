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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.agent.exceptions;

import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

/**
 * Unit tests for the agent configuration management exception classes.
 */
public class AgentConfigMgtExceptionTest {

    private static final String MESSAGE = "Something went wrong.";
    private static final String ERROR_CODE = "65023";

    @Test
    public void testBaseExceptionWithArgs() {

        Throwable cause = new RuntimeException("cause");
        AgentConfigMgtException e = new AgentConfigMgtException(MESSAGE, ERROR_CODE, cause);

        assertEquals(e.getMessage(), MESSAGE);
        assertEquals(e.getErrorCode(), ERROR_CODE);
        assertEquals(e.getCause(), cause);
    }

    @Test
    public void testBaseExceptionDefaultConstructor() {

        AgentConfigMgtException e = new AgentConfigMgtException();

        assertNull(e.getErrorCode());
    }

    @Test
    public void testServerException() {

        Throwable cause = new RuntimeException("cause");
        AgentConfigMgtServerException e = new AgentConfigMgtServerException(MESSAGE, ERROR_CODE, cause);

        assertTrue(e instanceof AgentConfigMgtException);
        assertEquals(e.getErrorCode(), ERROR_CODE);
        assertEquals(e.getMessage(), MESSAGE);
        assertNull(new AgentConfigMgtServerException().getErrorCode());
    }

    @Test
    public void testClientException() {

        Throwable cause = new RuntimeException("cause");
        AgentConfigMgtClientException e = new AgentConfigMgtClientException(MESSAGE, ERROR_CODE, cause);

        assertTrue(e instanceof AgentConfigMgtException);
        assertEquals(e.getErrorCode(), ERROR_CODE);
        assertEquals(e.getMessage(), MESSAGE);
        assertNull(new AgentConfigMgtClientException().getErrorCode());
    }
}
