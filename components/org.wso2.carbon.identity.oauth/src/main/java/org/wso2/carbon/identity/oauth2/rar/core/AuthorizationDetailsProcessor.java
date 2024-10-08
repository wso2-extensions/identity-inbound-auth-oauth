/*
 * Copyright (c) 2024, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.rar.core;

import org.wso2.carbon.identity.oauth2.IdentityOAuth2ServerException;
import org.wso2.carbon.identity.oauth2.rar.exception.AuthorizationDetailsProcessingException;
import org.wso2.carbon.identity.oauth2.rar.model.AuthorizationDetail;
import org.wso2.carbon.identity.oauth2.rar.model.AuthorizationDetails;
import org.wso2.carbon.identity.oauth2.rar.model.AuthorizationDetailsContext;
import org.wso2.carbon.identity.oauth2.rar.model.ValidationResult;

/**
 * The {@code AuthorizationDetailsProcessor} interface defines a contract for implementing
 * different types of authorization detail providers in a Service Provider Interface (SPI) setup.
 * <p>
 * Implementing classes are expected to provide mechanisms to validate, enrich, and identify
 * authorization details specific to various types.
 * </p>
 *
 * @see <a href="https://docs.oracle.com/javase%2Ftutorial%2F/sound/SPI-intro.html">Java SPI</a>
 */
public interface AuthorizationDetailsProcessor {

    /**
     * Validates the provided authorization details context when a new Rich Authorization Request is received.
     * <p>
     * This method is invoked once a new Rich Authorization Request is received to ensure that the
     * authorization details are valid and meet the required criteria. The validation logic should
     * be specific to the type of authorization details handled by the implementing class.
     * </p>
     *
     * @param authorizationDetailsContext the context containing the authorization details to be validated.
     * @return a {@code ValidationResult} indicating the outcome of the validation process. Returns a valid result
     * if the authorization details are correct and meet the criteria, otherwise returns an invalid result with an
     * appropriate error message.
     * @throws AuthorizationDetailsProcessingException if the validation fails due to a request error and the
     *                                                 authorization flow needs to be interrupted.
     * @throws IdentityOAuth2ServerException           if the validation fails due to a server error and the
     *                                                 authorization flow needs to be interrupted.
     * @see AuthorizationDetailsContext
     * @see ValidationResult
     */
    ValidationResult validate(AuthorizationDetailsContext authorizationDetailsContext)
            throws AuthorizationDetailsProcessingException, IdentityOAuth2ServerException;

    /**
     * Retrieves the type of authorization details handled by this provider.
     * <p>
     * Each implementation should return a unique type identifier that represents the kind of
     * authorization details it processes. This identifier is used to differentiate between
     * various providers in a service-oriented architecture.
     * </p>
     *
     * @return a {@code String} representing the type of authorization details managed by this provider
     * @see AuthorizationDetail#getType()
     */
    String getType();

    /**
     * Checks if the requested authorization detail is equal to or a subset of the existing authorization details.
     *
     * <p>This method verifies if the provided {@code requestedAuthorizationDetail} is either exactly the same as or
     * a subset of the {@code existingAuthorizationDetails} that have been previously accepted by the resource owner.
     *
     * @param requestedAuthorizationDetail The {@link AuthorizationDetail} being requested by the client.
     * @param existingAuthorizationDetails The set of {@link AuthorizationDetail} that have been previously accepted
     *                                     by the resource owner.
     * @return {@code true} if the requested authorization detail is equal to or a subset of the existing
     * authorization details, {@code false} otherwise.
     */
    boolean isEqualOrSubset(AuthorizationDetail requestedAuthorizationDetail,
                            AuthorizationDetails existingAuthorizationDetails);

    /**
     * <p>
     * This method is invoked prior to presenting the consent UI to the user. Its purpose is to
     * enhance or augment the authorization details, providing additional context or information
     * that may be necessary for informed consent. This may include adding more descriptive
     * information, default values, or other relevant details that are crucial for the user to
     * understand the authorization request fully.
     * </p>
     * <p>
     * It is also a responsibility of this method to generate a human-readable consent
     * description from the provided authorization details, which will be displayed to the user for approval.
     * The consent description should provide a clear, human-readable summary of the {@code authorization_details}
     * object.
     * </p>
     * <p>
     * This enrichment process aligns with the concepts outlined in
     * <a href="https://datatracker.ietf.org/doc/html/rfc9396#name-enriched-authorization-deta">RFC 9396</a>,
     * which describes the requirements for enriched authorization details to ensure clarity and transparency
     * in consent management.
     * </p>
     *
     * @param authorizationDetailsContext the context containing the authorization details to be enriched.
     * @return an enriched {@code AuthorizationDetail} object with additional information or context.
     * This enriched object is intended to provide users with a clearer understanding of the
     * authorization request when they are presented with the consent form.
     * @see AuthorizationDetailsContext
     * @see AuthorizationDetail
     * @see AuthorizationDetail#setConsentDescription
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc9396#name-enriched-authorization-deta">
     * Enriched Authorization Details</a>
     */
    AuthorizationDetail enrich(AuthorizationDetailsContext authorizationDetailsContext);
}
