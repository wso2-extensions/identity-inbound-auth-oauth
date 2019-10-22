package org.wso2.carbon.identity.oauth2.device.response;

import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.error.OAuthError;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.validators.AbstractValidator;
import org.wso2.carbon.identity.oauth2.device.constants.Constants;

import javax.servlet.http.HttpServletRequest;

public class DeviceFlowResponseTypeValidator extends AbstractValidator<HttpServletRequest> {

    public DeviceFlowResponseTypeValidator() {

        this.requiredParams.add(Constants.RESPONSE_TYPE);
        this.requiredParams.add(Constants.CLIENT_ID);

    }

    @Override
    public void validateMethod(HttpServletRequest request) throws OAuthProblemException {

        String method = request.getMethod();
        if (!OAuth.HttpMethod.GET.equals(method) && !OAuth.HttpMethod.POST.equals(method)) {
            throw OAuthProblemException.error(OAuthError.CodeResponse.INVALID_REQUEST)
                    .description("Method not correct.");
        }
    }

    @Override
    public void validateContentType(HttpServletRequest request) throws OAuthProblemException {

    }
}
