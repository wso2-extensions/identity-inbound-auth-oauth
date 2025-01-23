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

package org.wso2.carbon.identity.oauth.rar.model;

import java.util.Map;

/**
 * Represents the result of authorization details validation operation, encapsulating the status, reason for failure,
 * and additional metadata.
 * <p>
 * This class provides a way to create validation results that can be either valid or invalid, with
 * optional metadata for further context.
 * </p>
 */
public class ValidationResult {

    private final boolean status;
    private final String reason;
    private final Map<String, Object> meta;

    /**
     * Constructs a new {@code ValidationResult}.
     *
     * @param status whether the validation is successful.
     * @param reason the reason for validation failure, if applicable.
     * @param meta   additional metadata related to the validation result.
     */
    public ValidationResult(final boolean status, final String reason, final Map<String, Object> meta) {
        this.status = status;
        this.reason = reason;
        this.meta = meta;
    }

    /**
     * Creates a new {@code ValidationResult} indicating a successful validation.
     * <p>
     * This method should be used to indicate that the validation passed without any issues.
     * </p>
     *
     * @return a {@code ValidationResult} indicating a successful validation.
     */
    public static ValidationResult valid() {
        return new ValidationResult(true, null, null);
    }

    /**
     * Creates a new {@code ValidationResult} indicating a failed validation with a specified reason.
     * <p>
     * This method should be used to indicate that the validation failed and provide a reason for the failure.
     * </p>
     *
     * @param reason the reason why the validation failed.
     * @return a {@code ValidationResult} indicating a failed validation.
     */
    public static ValidationResult invalid(final String reason) {
        return new ValidationResult(false, reason, null);
    }

    /**
     * Creates a new {@code ValidationResult} indicating a failed validation with a specified reason and metadata.
     * <p>
     * This method should be used to indicate that the validation failed, provide a reason, and include
     * additional context or metadata.
     * </p>
     *
     * @param reason the reason why the validation failed.
     * @param meta   additional metadata related to the validation result.
     * @return a {@code ValidationResult} indicating a failed validation with metadata.
     */
    public static ValidationResult invalid(final String reason, final Map<String, Object> meta) {
        return new ValidationResult(false, reason, meta);
    }

    /**
     * Returns whether the validation was successful.
     *
     * @return {@code true} if the validation was successful, {@code false} otherwise.
     */
    public boolean isValid() {
        return this.status;
    }

    /**
     * Returns whether the validation failed.
     *
     * @return {@code true} if the validation failed, {@code false} otherwise.
     */
    public boolean isInvalid() {
        return !this.isValid();
    }

    /**
     * Returns the reason for validation failure, if applicable.
     *
     * @return the reason for validation failure, or {@code null} if the validation was successful.
     */
    public String getReason() {
        return this.reason;
    }

    /**
     * Returns additional metadata related to the validation result.
     *
     * @return an unmodifiable map of metadata, or an empty map if no metadata is present.
     */
    public Map<String, Object> getMeta() {
        return this.meta;
    }

    @Override
    public String toString() {
        return "ValidationResult{" +
                "status=" + status +
                ", reason='" + reason + '\'' +
                ", meta=" + meta +
                '}';
    }
}
