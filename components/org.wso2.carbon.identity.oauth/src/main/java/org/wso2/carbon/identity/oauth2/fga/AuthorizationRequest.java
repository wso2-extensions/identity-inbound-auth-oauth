package org.wso2.carbon.identity.oauth2.fga;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.annotations.ApiModelProperty;
import java.util.Objects;
import javax.validation.Valid;

public class AuthorizationRequest {

    private AccessCheckRequestSubject subject;
    private AccessCheckRequestResource resource;
    private AccessCheckRequestRelation relation;

    /**
     **/
    public AuthorizationRequest subject(AccessCheckRequestSubject subject) {

        this.subject = subject;
        return this;
    }

    @ApiModelProperty(value = "")
    @JsonProperty("subject")
    @Valid
    public AccessCheckRequestSubject getSubject() {
        return subject;
    }
    public void setSubject(AccessCheckRequestSubject subject) {
        this.subject = subject;
    }

    /**
     **/
    public AuthorizationRequest resource(AccessCheckRequestResource resource) {

        this.resource = resource;
        return this;
    }

    @ApiModelProperty(value = "")
    @JsonProperty("resource")
    @Valid
    public AccessCheckRequestResource getResource() {
        return resource;
    }
    public void setResource(AccessCheckRequestResource resource) {
        this.resource = resource;
    }

    /**
     **/
    public AuthorizationRequest relation(AccessCheckRequestRelation relation) {

        this.relation = relation;
        return this;
    }

    @ApiModelProperty(value = "")
    @JsonProperty("relation")
    @Valid
    public AccessCheckRequestRelation getRelation() {
        return relation;
    }
    public void setRelation(AccessCheckRequestRelation relation) {
        this.relation = relation;
    }



    @Override
    public boolean equals(java.lang.Object o) {

        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        AuthorizationRequest accessCheckRequest = (AuthorizationRequest) o;
        return Objects.equals(this.subject, accessCheckRequest.subject) &&
                Objects.equals(this.resource, accessCheckRequest.resource) &&
                Objects.equals(this.relation, accessCheckRequest.relation);
    }

    @Override
    public int hashCode() {
        return Objects.hash(subject, resource, relation);
    }

    @Override
    public String toString() {

        StringBuilder sb = new StringBuilder();
        sb.append("class AccessCheckRequest {\n");

        sb.append("    subject: ").append(toIndentedString(subject)).append("\n");
        sb.append("    resource: ").append(toIndentedString(resource)).append("\n");
        sb.append("    relation: ").append(toIndentedString(relation)).append("\n");
        sb.append("}");
        return sb.toString();
    }

    /**
     * Convert the given object to string with each line indented by 4 spaces
     * (except the first line).
     */
    private String toIndentedString(java.lang.Object o) {

        if (o == null) {
            return "null";
        }
        return o.toString().replace("\n", "\n");
    }
}
