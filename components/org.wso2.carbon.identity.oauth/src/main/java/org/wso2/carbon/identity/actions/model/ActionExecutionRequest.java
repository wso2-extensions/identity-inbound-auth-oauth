/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.actions.model;

import org.apache.commons.lang.StringUtils;
import org.slf4j.MDC;
import org.wso2.carbon.identity.actions.ActionType;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;

import java.util.List;

/**
 * Action Invocation Request.
 */
public class ActionExecutionRequest {

    private final ActionType actionType;
    private final String flowId;
    private final Event event;
    private final List<AllowedOperation> allowedOperations;

    public ActionExecutionRequest(Builder builder) {

        this.actionType = builder.actionType;
        this.flowId = builder.flowId;
        this.event = builder.event;
        this.allowedOperations = builder.allowedOperations;
    }

    // todo: read from a util class
    private static String getCorrelationId() {

        String ref;
        if (isCorrelationIDPresent()) {
            ref = MDC.get(FrameworkUtils.CORRELATION_ID_MDC);
        } else {
//            if (log.isDebugEnabled()) {
//                log.debug("Correlation id is not present in the log MDC.");
//            }
            ref = StringUtils.EMPTY;
        }
        return ref;
    }

    // todo: read from a util class
    private static boolean isCorrelationIDPresent() {

        return MDC.get(FrameworkUtils.CORRELATION_ID_MDC) != null;
    }

    public ActionType getActionType() {

        return actionType;
    }

    public String getFlowId() {

        return flowId;
    }

    public String getRequestId() {

        return getCorrelationId();
    }

    public Event getEvent() {

        return event;
    }

    public List<AllowedOperation> getAllowedOperations() {

        return allowedOperations;
    }

    public static class Builder {

        private ActionType actionType;
        private String flowId;
        private Event event;
        private List<AllowedOperation> allowedOperations;

        public Builder actionType(ActionType actionType) {

            this.actionType = actionType;
            return this;
        }

        public Builder flowId(String flowId) {

            this.flowId = flowId;
            return this;
        }

        public Builder event(Event event) {

            this.event = event;
            return this;
        }

        public Builder allowedOperations(List<AllowedOperation> allowedOperations) {

            this.allowedOperations = allowedOperations;
            return this;
        }

        public ActionExecutionRequest build() {

            return new ActionExecutionRequest(this);
        }
    }
}

