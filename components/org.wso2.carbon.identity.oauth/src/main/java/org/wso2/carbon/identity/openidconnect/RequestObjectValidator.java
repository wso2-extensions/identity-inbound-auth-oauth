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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.openidconnect;

import org.wso2.carbon.identity.oauth2.RequestObjectException;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;

/**
 * This class validates request object parameter value which comes with the OIDC authorization request as an optional
 * parameter
 */
public interface RequestObjectValidator {

    /**
     * Validates Signature of the requestObject jwt
     *
     * @param requestObject requestObject
     */
    public void validateSignature(String requestObject) throws RequestObjectException;

    /**
     * To decrypt the request objected by using IS primary key
     *
     * @param requestObject    requestObject
     * @param oAuth2Parameters oAuth2Parameters
     * @throws RequestObjectException
     */
    public void decrypt(String requestObject, OAuth2Parameters oAuth2Parameters) throws RequestObjectException;

    /**
     * To validate request object
     *
     * @param requestObject    requestObject
     * @param oAuth2Parameters oAuth2Parameters
     * @throws RequestObjectException
     */
    public void validateRequestObject(String requestObject, OAuth2Parameters oAuth2Parameters)
            throws RequestObjectException;

    /**
     * To get the payload value of the requested object if it is encoded or decrpyted
     *
     * @return payload value
     */
    public String getPayload();

}

