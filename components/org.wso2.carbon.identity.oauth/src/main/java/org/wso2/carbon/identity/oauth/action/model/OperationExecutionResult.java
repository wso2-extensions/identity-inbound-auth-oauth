package org.wso2.carbon.identity.oauth.action.model;

import org.wso2.carbon.identity.action.execution.model.PerformableOperation;

/**
 * This class represents the result of the execution of an operation.
 * It contains the operation that was executed, the status of the execution and a message.
 * This is used to summarize the operations performed based on action response.
 */
public class OperationExecutionResult {

    private final PerformableOperation operation;
    private final Status status;
    private final String message;

    public OperationExecutionResult(PerformableOperation operation, Status status, String message) {

        this.operation = operation;
        this.status = status;
        this.message = message;
    }

    public PerformableOperation getOperation() {

        return operation;
    }

    public Status getStatus() {

        return status;
    }

    public String getMessage() {

        return message;
    }

    /**
     * Enum to represent the status of the operation execution.
     */
    public enum Status {
        SUCCESS, FAILURE
    }
}
