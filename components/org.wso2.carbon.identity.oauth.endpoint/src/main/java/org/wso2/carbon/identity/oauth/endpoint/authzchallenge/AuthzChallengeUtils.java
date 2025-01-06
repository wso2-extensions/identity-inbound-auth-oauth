package org.wso2.carbon.identity.oauth.endpoint.authzchallenge;

import static org.wso2.carbon.identity.oauth.endpoint.state.OAuthAuthorizeState.INITIAL_REQUEST;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.endpoint.api.auth.model.StepTypeEnum;
import org.wso2.carbon.identity.oauth.endpoint.message.OAuthMessage;

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
