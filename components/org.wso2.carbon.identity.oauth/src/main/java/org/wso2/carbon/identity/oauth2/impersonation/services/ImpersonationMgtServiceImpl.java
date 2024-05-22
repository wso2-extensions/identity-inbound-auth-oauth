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

package org.wso2.carbon.identity.oauth2.impersonation.services;

import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.impersonation.models.ImpersonationContext;
import org.wso2.carbon.identity.oauth2.impersonation.models.ImpersonationRequestDTO;
import org.wso2.carbon.identity.oauth2.impersonation.validators.ImpersonationValidator;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;

import java.util.List;

/**
 * The {@code ImpersonationMgtServiceImpl} class implements the {@link ImpersonationMgtService} interface
 * and provides functionality for validating impersonation requests.
 */
public class ImpersonationMgtServiceImpl implements ImpersonationMgtService {

    /**
     * {@inheritDoc}
     */
    @Override
    public ImpersonationContext validateImpersonationRequest(ImpersonationRequestDTO impersonationRequestDTO)
            throws IdentityOAuth2Exception {

        List<ImpersonationValidator> impersonationValidators = OAuth2ServiceComponentHolder.getInstance()
                .getImpersonationValidators();

        ImpersonationContext impersonationContext = new ImpersonationContext();
        impersonationContext.setImpersonationRequestDTO(impersonationRequestDTO);

        for (ImpersonationValidator impersonationValidator: impersonationValidators) {
            impersonationContext = impersonationValidator.validateImpersonation(impersonationContext);

            if (!impersonationContext.isValidated()) {
                return impersonationContext;
            }
        }
        return impersonationContext;
    }
}
