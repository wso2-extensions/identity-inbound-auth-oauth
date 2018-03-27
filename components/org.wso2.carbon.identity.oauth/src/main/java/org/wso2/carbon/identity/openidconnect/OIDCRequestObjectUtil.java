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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.as.request.OAuthAuthzRequest;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.RequestObjectException;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.model.RequestObject;

/**
 * According to the OIDC spec requestObject is passed as a query param value of request/request_uri parameters. This is
 * associated with OIDC authorization request. This class is used to select the corresponding builder class and build the
 * request object according to the parameter.
 */
public class OIDCRequestObjectUtil {

    private static final Log log = LogFactory.getLog(OIDCRequestObjectUtil.class);
    private static final String REQUEST = "request";
    private static final String REQUEST_URI = "request_uri";
    private static final String REQUEST_PARAM_VALUE_BUILDER = "request_param_value_builder";
    private static final String REQUEST_URI_PARAM_VALUE_BUILDER = "request_uri_param_value_builder";

    /**
     * Fetch and invoke the matched request builder class based on the identity.xml configurations.
     * Build and validate the Request Object extracted from request information
     *
     * @param oauthRequest authorization request
     * @throws RequestObjectException
     */
    public static RequestObject buildRequestObject(OAuthAuthzRequest oauthRequest, OAuth2Parameters oAuth2Parameters)
            throws RequestObjectException {
        /*
          So that the request is a valid OAuth 2.0 Authorization Request, values for the response_type and client_id
          parameters MUST be included using the OAuth 2.0 request syntax, since they are REQUIRED by OAuth 2.0.
          The values for these parameters MUST match those in the Request Object, if present
         */
        RequestObject requestObject;
        RequestObjectBuilder requestObjectBuilder;
        String requestObjType;
        if (isRequestParameter(oauthRequest)) {
            requestObjectBuilder = getRequestObjectBuilder(REQUEST_PARAM_VALUE_BUILDER);
            requestObjType = REQUEST;
        } else if (isRequestUri(oauthRequest)) {
            requestObjectBuilder = getRequestObjectBuilder(REQUEST_URI_PARAM_VALUE_BUILDER);
            requestObjType = REQUEST_URI;

        } else {
            // Unsupported request object type.
            return null;
        }

        if (requestObjectBuilder == null) {
            String error = "Unable to build the OIDC Request Object from:";
            throw new RequestObjectException(OAuth2ErrorCodes.SERVER_ERROR, error + requestObjType);
        }
        requestObject = requestObjectBuilder.buildRequestObject(oauthRequest.getParam(requestObjType),
                oAuth2Parameters);
        RequestObjectValidator requestObjectValidator = OAuthServerConfiguration.getInstance()
                .getRequestObjectValidator();

        validateRequestObjectSignature(oAuth2Parameters, requestObject, requestObjectValidator);

        if (!requestObjectValidator.validateRequestObject(requestObject, oAuth2Parameters)) {
            throw new RequestObjectException(OAuth2ErrorCodes.INVALID_REQUEST, "Invalid parameters " +
                    "found in the Request Object.");

        }
        if (log.isDebugEnabled()) {
            log.debug("Successfully build and and validated request Object for: " + requestObjType);
        }
        return requestObject;
    }

    private static void validateRequestObjectSignature(OAuth2Parameters oAuth2Parameters,
                                                       RequestObject requestObject,
                                                       RequestObjectValidator requestObjectValidator)
            throws RequestObjectException {

        String clientId = oAuth2Parameters.getClientId();
        OAuthAppDO oAuthAppDO;
        try {
            oAuthAppDO = OAuth2Util.getAppInformationByClientId(clientId);
        } catch (IdentityOAuth2Exception | InvalidOAuthClientException e) {
            throw new RequestObjectException("Error while retrieving app information for client_id: " + clientId +
                    ". Cannot proceed with signature validation", e);
        }

        // Check whether request object signature validation is enforced.
        if (oAuthAppDO.isRequestObjectSignatureValidationEnabled()) {
            if (log.isDebugEnabled()) {
                log.debug("Request Object Signature Verification enabled for client_id: " + clientId);
            }
            if (requestObject.isSigned()) {
                validateSignature(oAuth2Parameters, requestObject, requestObjectValidator);
            } else {
                // If request object is not signed we need to throw an exception.
                throw new RequestObjectException("Request object signature validation is enabled but request object " +
                        "is not signed.");
            }
        } else {
            // Since request object signature validation is not enabled we will only validate the signature if
            // the request object is signed.
            if (requestObject.isSigned()) {
                validateSignature(oAuth2Parameters, requestObject, requestObjectValidator);
            }
        }
    }

    private static void validateSignature(OAuth2Parameters oAuth2Parameters,
                                          RequestObject requestObject,
                                          RequestObjectValidator requestObjectValidator) throws RequestObjectException {

        if (!requestObjectValidator.validateSignature(requestObject, oAuth2Parameters)) {
            throw new RequestObjectException(OAuth2ErrorCodes.INVALID_REQUEST,
                    "Request Object signature verification failed.");
        }
    }

    private static RequestObjectBuilder getRequestObjectBuilder(String requestParamValueBuilder) {

        return OAuthServerConfiguration.getInstance().getRequestObjectBuilders().get(requestParamValueBuilder);
    }

    private static boolean isRequestUri(OAuthAuthzRequest oAuthAuthzRequest) {

        return StringUtils.isNotBlank(oAuthAuthzRequest.getParam(REQUEST_URI));
    }

    private static boolean isRequestParameter(OAuthAuthzRequest oAuthAuthzRequest) {

        return StringUtils.isNotBlank(oAuthAuthzRequest.getParam(REQUEST));
    }
}
