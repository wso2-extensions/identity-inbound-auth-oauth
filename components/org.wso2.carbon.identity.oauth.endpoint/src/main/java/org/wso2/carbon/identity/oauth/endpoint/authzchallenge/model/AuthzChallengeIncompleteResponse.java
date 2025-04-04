package org.wso2.carbon.identity.oauth.endpoint.authzchallenge.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.wso2.carbon.identity.oauth.endpoint.api.auth.model.NextStep;

public class AuthzChallengeIncompleteResponse  extends AuthzChallengeGenericResponse {

    @JsonProperty("next_step")
    private NextStep nextStep;

    public AuthzChallengeIncompleteResponse() {

    }

    public AuthzChallengeIncompleteResponse(String authSession, String error, String errorDescription,
                                            NextStep nextStep) {

        super(authSession, error, errorDescription);
        this.nextStep = nextStep;
    }

    @JsonIgnore
    public NextStep getNextStep() {

        return nextStep;
    }

    public void setNextStep(NextStep nextStep) {

        this.nextStep = nextStep;
    }

}
