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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.test.common.testng.logger;

import org.apache.log4j.AppenderSkeleton;
import org.apache.log4j.spi.LoggingEvent;

/**
 * Log4J Log Appender, which does nothing. Logs simply goes into a black hole.
 * This is primarily used to skip DEBUG and INFO logs being printed by testNg unit tests.
 * We create multiple unit test(s) and suite(s) for each DEBUG and INFO log levels to get the proper
 * coverage.
 *
 * Printing all the logs into the console clutters the console, makes the test execution slow and causes OOM.
 *
 * Null Appender helps to prevent the above problems.
 */
public class NullAppender extends AppenderSkeleton {

    @Override
    protected void append(LoggingEvent loggingEvent) {

    }

    @Override
    public void close() {

    }

    @Override
    public boolean requiresLayout() {
        return false;
    }
}
