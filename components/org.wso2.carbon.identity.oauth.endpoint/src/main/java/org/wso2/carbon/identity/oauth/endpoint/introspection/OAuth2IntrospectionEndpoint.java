/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.oauth.endpoint.introspection;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONException;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.oauth2.OAuth2TokenValidationService;
import org.wso2.carbon.identity.oauth2.dto.OAuth2IntrospectionResponseDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;

import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

@Path("/introspect")
@Consumes({MediaType.APPLICATION_FORM_URLENCODED})
@Produces(MediaType.APPLICATION_JSON)
public class OAuth2IntrospectionEndpoint {

    private final static Log log = LogFactory.getLog(OAuth2IntrospectionEndpoint.class);
    private final static String DEFAULT_TOKEN_TYPE_HINT = "bearer";
    private final static String DEFAULT_TOKEN_TYPE = "Bearer";
    private final static String JWT_TOKEN_TYPE = "JWT";

    /**
     * @param token access token or refresh token
     * @return
     */
    @POST
    public Response introspect(@FormParam("token") String token) {
        return introspect(token, DEFAULT_TOKEN_TYPE_HINT);
    }

    /**
     * @param token         access token or refresh token
     * @param tokenTypeHint hint for the type of the token submitted for introspection
     * @return
     */
    @POST
    public Response introspect(@FormParam("token") String token, @FormParam("token_type_hint") String tokenTypeHint) {

        OAuth2TokenValidationRequestDTO introspectionRequest;
        OAuth2IntrospectionResponseDTO introspectionResponse;

        if (tokenTypeHint == null) {
            tokenTypeHint = DEFAULT_TOKEN_TYPE_HINT;
        }

        if (log.isDebugEnabled()) {
            log.debug("Token type hint: " + tokenTypeHint);
        }

        if (StringUtils.isBlank(token)) {
            return Response.status(Response.Status.BAD_REQUEST).entity("{\"error\": \"Invalid input\"}").build();
        }

        // validate the access token against the OAuth2TokenValidationService OSGi service.
        introspectionRequest = new OAuth2TokenValidationRequestDTO();
        OAuth2TokenValidationRequestDTO.OAuth2AccessToken accessToken = introspectionRequest.new OAuth2AccessToken();
        accessToken.setIdentifier(token);
        accessToken.setTokenType(tokenTypeHint);
        introspectionRequest.setAccessToken(accessToken);

        OAuth2TokenValidationService tokenService = (OAuth2TokenValidationService) PrivilegedCarbonContext
                .getThreadLocalCarbonContext().getOSGiService(OAuth2TokenValidationService.class);

        introspectionResponse = tokenService.buildIntrospectionResponse(introspectionRequest);

        if (introspectionResponse.getError() != null) {
            if (log.isDebugEnabled()) {
                log.debug("The error why token is made inactive: " + introspectionResponse.getError());
            }
            return Response.status(Response.Status.OK).entity("{\"active\":false}").build();
        }

        IntrospectionResponseBuilder respBuilder = new IntrospectionResponseBuilder()
                .setActive(introspectionResponse.isActive())
                .setNotBefore(introspectionResponse.getNbf())
                .setScope(introspectionResponse.getScope())
                .setUsername(introspectionResponse.getUsername())
                .setTokenType(DEFAULT_TOKEN_TYPE)
                .setTokenBindingHash(introspectionResponse.getTbh())
                .setClientId(introspectionResponse.getClientId())
                .setIssuedAt(introspectionResponse.getIat())
                .setExpiration(introspectionResponse.getExp());

        if (tokenTypeHint.equalsIgnoreCase(JWT_TOKEN_TYPE)) {
            respBuilder.setAudience(introspectionResponse.getAud())
                    .setJwtId(introspectionResponse.getJti())
                    .setSubject(introspectionResponse.getSub())
                    .setTokenType(JWT_TOKEN_TYPE)
                    .setIssuer(introspectionResponse.getIss());
        }

        try {
            return Response.ok(respBuilder.build(), MediaType.APPLICATION_JSON).status(Response.Status.OK).build();
        } catch (JSONException e) {
            log.error("Error occured while building the json response.", e);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("{'error': 'Error occured while building the json response.'}").build();
        }
    }
}
