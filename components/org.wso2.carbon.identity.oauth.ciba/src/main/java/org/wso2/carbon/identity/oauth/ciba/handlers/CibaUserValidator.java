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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.ciba.handlers;

import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaClientException;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeRequest;

/**
 * Pluggable validator that runs additional checks on the user resolved for a CIBA authentication
 * request. Multiple validators can be registered as OSGi services; each validator decides whether
 * it applies to a given request via {@link #isApplicable(CibaAuthCodeRequest)} and, when it does, runs
 * its checks in {@link #validate(CibaUserResolver.ResolvedUser, CibaAuthCodeRequest, String)}.
 */
public interface CibaUserValidator {

    /**
     * Determines whether this validator should be executed for the given CIBA request.
     *
     * @param cibaAuthCodeRequest The CIBA authentication request.
     * @return {@code true} if this validator applies to the request, {@code false} otherwise.
     */
    boolean isApplicable(CibaAuthCodeRequest cibaAuthCodeRequest);

    /**
     * Validates the resolved user against the CIBA request context. Implementations must throw a
     * {@link CibaClientException} when the user fails validation.
     *
     * @param resolvedUser        The user resolved from the CIBA request.
     * @param cibaAuthCodeRequest The CIBA authentication request.
     * @param tenantDomain        The tenant domain of the request.
     * @throws CibaClientException If the resolved user fails validation.
     * @throws CibaCoreException   If validation could not be completed due to a server-side error.
     */
    void validate(CibaUserResolver.ResolvedUser resolvedUser, CibaAuthCodeRequest cibaAuthCodeRequest,
                  String tenantDomain) throws CibaClientException, CibaCoreException;
}
