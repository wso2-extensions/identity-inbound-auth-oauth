package org.wso2.carbon.identity.oauth.endpoint.authzchallenge;

import java.net.URI;
import java.net.URISyntaxException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.Response;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.error.OAuthError;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.endpoint.api.auth.model.StepTypeEnum;
import org.wso2.carbon.identity.oauth.endpoint.authz.OAuth2AuthzEndpoint;
import org.wso2.carbon.identity.oauth.endpoint.message.OAuthMessage;
import org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import static org.wso2.carbon.identity.oauth.endpoint.state.OAuthAuthorizeState.INITIAL_REQUEST;

public class AuthzChallengeUtils {

    private static final Log log = LogFactory.getLog(AuthzChallengeUtils.class);

    private AuthzChallengeUtils() {

    }

    // Used to validate request
    public static boolean validateRequest(OAuthMessage oAuthMessage) {
        return oAuthMessage.getClientId() != null;
    }

    public static boolean isInitialRequest(OAuthMessage oAuthMessage) {
        return INITIAL_REQUEST.equals(oAuthMessage.getRequestType());

//        return oAuthMessage.getRequest().getParameter(OAuth2Util.CLIENT_ID) != null && oAuthMessage.getRequest().getAttribute(OAuthConstants.AUTH_SESSION) == null
//                && oAuthMessage.getRequest().getParameter(OAuthConstants.SESSION_DATA_KEY_CONSENT) == null;
    }

    private StepTypeEnum getStepType(boolean isMultiOps) {

        if (isMultiOps) {
            return StepTypeEnum.MULTI_OPTIONS_PROMPT;
        } else {
            return StepTypeEnum.AUTHENTICATOR_PROMPT;
        }
    }





}
