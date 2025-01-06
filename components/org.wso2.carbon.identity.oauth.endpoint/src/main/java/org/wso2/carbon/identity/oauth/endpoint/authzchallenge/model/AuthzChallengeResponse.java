package org.wso2.carbon.identity.oauth.endpoint.authzchallenge.model;

import org.wso2.carbon.identity.application.authentication.framework.util.auth.service.AuthServiceConstants;
import org.wso2.carbon.identity.oauth.endpoint.api.auth.model.FlowTypeEnum;
import org.wso2.carbon.identity.oauth.endpoint.api.auth.model.NextStep;

public class AuthzChallengeResponse {
    private String auth_session;
    private String error;
    private String error_description;
    private AuthServiceConstants.FlowStatus flowStatus;
    private FlowTypeEnum flowType = FlowTypeEnum.AUTHENTICATION;
    private NextStep nextStep;

    public AuthzChallengeResponse(){

    }

    public AuthzChallengeResponse(String auth_session, String error, String error_description, AuthServiceConstants.FlowStatus flowStatus, FlowTypeEnum flowType, NextStep nextStep){
        this.auth_session = auth_session;
        this.error = error;
        this.error_description = error_description;
        this.flowStatus = flowStatus;
        this.flowType = flowType;
        this.nextStep = nextStep;
    }

    public String getAuth_session(){
        return auth_session;
    }

    public void setAuth_session(String auth_session){
        this.auth_session = auth_session;
    }

    public String getError(){
        return error;
    }

    public void setError(String error){
        this.error = error;
    }

    public String getError_description(){
        return error_description;
    }

    public void setError_description(String error_description){
        this.error_description = error_description;
    }

    public AuthServiceConstants.FlowStatus getFlowStatus(){
        return flowStatus;
    }

    public void setFlowStatus(AuthServiceConstants.FlowStatus flowStatus){
        this.flowStatus = flowStatus;
    }

    public FlowTypeEnum getFlowType(){
        return flowType;
    }

    public void setFlowType(FlowTypeEnum flowType){
        this.flowType = flowType;
    }

    public NextStep getNextStep(){
        return nextStep;
    }

    public void setNextStep(NextStep nextStep){
        this.nextStep = nextStep;
    }

}
