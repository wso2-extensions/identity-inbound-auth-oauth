package org.wso2.carbon.identity.oauth2.rar.handler;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONArray;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.rar.common.model.AuthorizationDetails;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.response.AccessTokenResponseHandler;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 *
 */
public class RARAccessTokenResponseHandler implements AccessTokenResponseHandler {
    private static final ObjectMapper OBJECT_MAPPER = new JsonMapper();
    private static final Log LOG = LogFactory.getLog(RARAccessTokenResponseHandler.class);

    @Override
//    public Map<String, Object> getAdditionalTokenResponseAttributes(OAuthTokenReqMessageContext tokReqMsgCtx)
//            throws IdentityOAuth2Exception {
//
//        List<AuthorizationDetails> authorizationDetails = AuthorizationDetailService.getInstance()
//                .getConsentedAuthorizationDetailsByAuthzCode(tokReqMsgCtx.getOauth2AccessTokenReqDTO()
//                .getAuthorizationCode());
//
//        Map<String, Object> additionalAttributes = new HashMap<>();
//        if (isNotEmptyList(authorizationDetails)) {
//            additionalAttributes.put(AUTHORIZATION_DETAILS, convertToJsonArray(authorizationDetails));
//        }
//        return additionalAttributes;
//    }

    public Map<String, Object> getAdditionalTokenResponseAttributes(OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception {

        Map<String, Object> additionalAttributes = new HashMap<>();

        return additionalAttributes;
    }


    private boolean isNotEmptyList(List<AuthorizationDetails> list) {
        return list != null && !list.isEmpty();
    }

    private JSONArray convertToJsonArray(List<AuthorizationDetails> authorizationDetails) {
        try {
            return OBJECT_MAPPER.convertValue(OBJECT_MAPPER.writeValueAsString(authorizationDetails), JSONArray.class);
        } catch (JsonProcessingException e) {
            LOG.error("Serialization error. Caused by, ", e);
        }
        return new JSONArray(authorizationDetails);
    }
}
