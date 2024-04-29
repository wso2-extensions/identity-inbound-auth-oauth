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

package org.wso2.carbon.identity.oauth.common;

import org.apache.commons.lang.StringUtils;
import org.apache.oltu.oauth2.as.validator.TokenValidator;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.error.OAuthError;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;

import javax.servlet.http.HttpServletRequest;

import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth20Params.REQUESTED_SUBJECT;

/**
 * This class implements a validator for custom response type "subject_token".
 * It extends the TokenValidator class and provides methods to validate the HTTP method and required parameters
 * in the subject_token response.
 */
public class SubjectTokenResponseValidator extends TokenValidator {

    /**
     * Validates the HTTP method used in the request.
     * Only GET and POST methods are allowed for subject_token response.
     *
     * @param request The HttpServletRequest object representing the incoming request.
     * @throws OAuthProblemException If the HTTP method is not GET or POST.
     */
    @Override
    public void validateMethod(HttpServletRequest request) throws OAuthProblemException {

        String method = request.getMethod();
        if (!OAuth.HttpMethod.GET.equals(method) && !OAuth.HttpMethod.POST.equals(method)) {
            throw OAuthProblemException.error(OAuthError.CodeResponse.INVALID_REQUEST)
                    .description("Http Method is not correct.");
        }
    }

    /**
     * Validates the required parameters for the subject_token response type.
     * The 'requested_subject' parameter contains the subject that the impersonator intends to impersonate.
     * The 'requested_subject' parameter should contain a valid string.
     *
     * @param request The HttpServletRequest object representing the incoming request.
     * @throws OAuthProblemException If the 'requested_subject' parameter is missing or blank.
     */
    public void validateRequiredParameters(HttpServletRequest request) throws OAuthProblemException {

        super.validateRequiredParameters(request);

        // for subject_token response type, the requestedSubject parameter should contain valid string.
        String requestedSubject = request.getParameter(REQUESTED_SUBJECT);
        if (StringUtils.isBlank(requestedSubject)) {
            throw OAuthProblemException.error(OAuthError.TokenResponse.INVALID_REQUEST)
                    .description("response_type is subject_token. " +
                            "but requested_subject parameter not found.");
        }
    }
}
