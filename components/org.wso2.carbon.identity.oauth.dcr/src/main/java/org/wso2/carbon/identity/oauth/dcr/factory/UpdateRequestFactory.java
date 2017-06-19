/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * you may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.dcr.factory;

import static org.wso2.carbon.identity.oauth.dcr.factory.HttpRegistrationResponseFactory.INVALID_CLIENT_METADATA;

import java.io.IOException;
import java.io.Reader;
import java.util.regex.Matcher;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.HttpMethod;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkClientException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityRequestFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.dcr.model.UpdateRequest;
import org.wso2.carbon.identity.oauth.dcr.model.UpdateRequestProfile;
import org.wso2.carbon.identity.oauth.dcr.util.DCRConstants;

/**
 * UpdateRequestFactory build the request for DCR Update Request.
 */
public class UpdateRequestFactory extends HttpIdentityRequestFactory {

    private static Log log = LogFactory.getLog(UpdateRequestFactory.class);

    @Override
    public boolean canHandle(HttpServletRequest request, HttpServletResponse response) {

        boolean canHandle = false;
        if (request != null) {
            Matcher matcher = DCRConstants.DCRM_ENDPOINT_CLIENT_CONFIGURATION_URL_PATTERN
                .matcher(request.getRequestURI());
            if (matcher.matches() && HttpMethod.PUT.equals(request.getMethod())) {
                canHandle = true;
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("canHandle " + canHandle + " by UpdateRequestFactory.");
        }
        return canHandle;
    }

    @Override
    public UpdateRequest.UpdateRequestBuilder create(HttpServletRequest request,
        HttpServletResponse response) throws FrameworkClientException {

        UpdateRequest.UpdateRequestBuilder updateRequestBuilder = new UpdateRequest
            .UpdateRequestBuilder(request, response);
        create(updateRequestBuilder, request, response);
        return updateRequestBuilder;
    }

    @Override
    public void create(IdentityRequest.IdentityRequestBuilder builder, HttpServletRequest request,
                        HttpServletResponse response) throws FrameworkClientException {

        UpdateRequest.UpdateRequestBuilder updateRequestBuilder =
            (UpdateRequest.UpdateRequestBuilder) builder;

        super.create(updateRequestBuilder, request, response);

        try {
            Reader requestBodyReader = request.getReader();
            JSONParser jsonParser = new JSONParser();
            JSONObject jsonData = (JSONObject) jsonParser.parse(requestBodyReader);
            if (log.isDebugEnabled()) {
                log.debug("DCR request json : " + jsonData.toJSONString());
            }

            UpdateRequestProfile updateRequestProfile = updateRequestBuilder
                .getUpdateRequestProfile();

            if (updateRequestProfile == null) {
                updateRequestProfile = new UpdateRequestProfile();
            }

            String consumerKey = null;
            Matcher matcher = DCRConstants.DCRM_ENDPOINT_CLIENT_CONFIGURATION_URL_PATTERN
                .matcher(request.getRequestURI());
            if (matcher.find()) {
                consumerKey = matcher.group(2);
            }

            updateRequestProfile.setConsumerKey(consumerKey);

            updateRequestProfile.setClientId((String) jsonData.get(UpdateRequest.
                UpdateRequestConstant.CLIENT_ID));
            updateRequestProfile.setClientSecret(
                (String) jsonData.get(UpdateRequest.UpdateRequestConstant.CLIENT_SECRET));
            updateRequestProfile.setClientName((String) jsonData.get(UpdateRequest
                .UpdateRequestConstant.CLIENT_NAME));

            Object object = jsonData.get(UpdateRequest.UpdateRequestConstant.REDIRECT_URIS);
            if (object instanceof JSONArray) {
                JSONArray redirectUris = (JSONArray) object;
                for (Object redirectUri : redirectUris) {
                    if (redirectUri instanceof String) {
                      updateRequestProfile.getRedirectUris().add((String) redirectUri);
                    }
                }
            } else if (object instanceof String) {
                updateRequestProfile.getRedirectUris().add((String) object);

            } else if (updateRequestProfile.getGrantTypes().contains(DCRConstants.GrantTypes
                .AUTHORIZATION_CODE) || updateRequestProfile.getGrantTypes().contains(DCRConstants
                .GrantTypes.IMPLICIT)) {
                throw IdentityException.error(FrameworkClientException.class,
                    "RedirectUris property must have at least one URI value.");
            }

            object = jsonData.get(UpdateRequest.UpdateRequestConstant.GRANT_TYPES);
            if (object != null && object instanceof JSONArray) {
                JSONArray grantTypes = (JSONArray) object;
                for (Object grantType : grantTypes) {
                    updateRequestProfile.getGrantTypes().add(grantType.toString());
                }
            } else if (object != null) {
                updateRequestProfile.getGrantTypes().add((String) object);
            }

            String username = CarbonContext.getThreadLocalCarbonContext().getUsername();
            updateRequestProfile.setUsername(username);
            updateRequestBuilder.setUpdateRequestProfile(updateRequestProfile);

        } catch (IOException e) {
            String errorMessage = "Error occurred while reading servlet request body, " +
                e.getMessage();
            throw IdentityException.error(FrameworkClientException.class, errorMessage, e);
        } catch (ParseException e) {
            String errorMessage = "Error occurred while parsing the json object, " + e.getMessage();
            throw  IdentityException.error(FrameworkClientException.class, errorMessage, e);
        }
    }

    @Override
    public HttpIdentityResponse.HttpIdentityResponseBuilder handleException(FrameworkClientException
        exception, HttpServletRequest request, HttpServletResponse response) {
        HttpIdentityResponse.HttpIdentityResponseBuilder builder =
            new HttpIdentityResponse.HttpIdentityResponseBuilder();
        String errorMessage = generateErrorResponse(INVALID_CLIENT_METADATA, exception.getMessage())
            .toJSONString();
        builder.setBody(errorMessage);
        builder.setStatusCode(HttpServletResponse.SC_BAD_REQUEST);
        builder.addHeader(OAuthConstants.HTTP_RESP_HEADER_CACHE_CONTROL,
            OAuthConstants.HTTP_RESP_HEADER_VAL_CACHE_CONTROL_NO_STORE);
        builder.addHeader(OAuthConstants.HTTP_RESP_HEADER_PRAGMA,
            OAuthConstants.HTTP_RESP_HEADER_VAL_PRAGMA_NO_CACHE);
        builder.addHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON);

        return builder;
    }

    protected JSONObject generateErrorResponse(String error, String description) {
        JSONObject obj = new JSONObject();
        obj.put("error", error);
        obj.put("error_description", description);
        return obj;
    }
}
