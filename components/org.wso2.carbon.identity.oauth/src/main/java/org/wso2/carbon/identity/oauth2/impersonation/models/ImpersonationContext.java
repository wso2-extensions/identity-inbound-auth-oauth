/*
 *  Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
 *
 *  WSO2 LLC. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.carbon.identity.oauth2.impersonation.models;

 /**
 * The object which will contain context information which are passed through Impersonation validation process.
 * The {@code ImpersonationContext} class represents the context for impersonation requests, including
 * information about the request, validation status, and any validation failure details.
 */
public class ImpersonationContext {

    private ImpersonationRequestDTO impersonationRequestDTO;
    private boolean isValidated;
    private String validationFailureErrorMessage;
    private String validationFailureErrorCode;


    public ImpersonationRequestDTO getImpersonationRequestDTO() {

        return impersonationRequestDTO;
    }

    public void setImpersonationRequestDTO(ImpersonationRequestDTO impersonationRequestDTO) {

        this.impersonationRequestDTO = impersonationRequestDTO;
    }

    public boolean isValidated() {

        return isValidated;
    }

    public void setValidated(boolean validated) {

        isValidated = validated;
    }

    public String getValidationFailureErrorMessage() {

        return validationFailureErrorMessage;
    }

    public void setValidationFailureErrorMessage(String validationFailureErrorMessage) {

        this.validationFailureErrorMessage = validationFailureErrorMessage;
    }

    public String getValidationFailureErrorCode() {

        return validationFailureErrorCode;
    }

    public void setValidationFailureErrorCode(String validationFailureErrorCode) {

        this.validationFailureErrorCode = validationFailureErrorCode;
    }
}
