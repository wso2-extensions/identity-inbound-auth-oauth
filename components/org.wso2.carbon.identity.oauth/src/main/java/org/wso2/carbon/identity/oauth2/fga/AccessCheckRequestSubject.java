package org.wso2.carbon.identity.oauth2.fga;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;


import io.swagger.annotations.*;
import java.util.Objects;
import javax.validation.Valid;

public class AccessCheckRequestSubject  {

    private String id;
    private String type;
    private String relation;

    /**
     **/
    public AccessCheckRequestSubject id(String id) {

        this.id = id;
        return this;
    }

    @ApiModelProperty(example = "user123", value = "")
    @JsonProperty("id")
    @Valid
    public String getId() {
        return id;
    }
    public void setId(String id) {
        this.id = id;
    }

    /**
     **/
    public AccessCheckRequestSubject type(String type) {

        this.type = type;
        return this;
    }

    @ApiModelProperty(example = "user", value = "")
    @JsonProperty("type")
    @Valid
    public String getType() {
        return type;
    }
    public void setType(String type) {
        this.type = type;
    }

    /**
     **/
    public AccessCheckRequestSubject relation(String relation) {

        this.relation = relation;
        return this;
    }

    @ApiModelProperty(example = "manager", value = "")
    @JsonProperty("relation")
    @Valid
    public String getRelation() {
        return relation;
    }
    public void setRelation(String relation) {
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
        AccessCheckRequestSubject accessCheckRequestSubject = (AccessCheckRequestSubject) o;
        return Objects.equals(this.id, accessCheckRequestSubject.id) &&
                Objects.equals(this.type, accessCheckRequestSubject.type) &&
                Objects.equals(this.relation, accessCheckRequestSubject.relation);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, type, relation);
    }

    @Override
    public String toString() {

        StringBuilder sb = new StringBuilder();
        sb.append("class AccessCheckRequestSubject {\n");

        sb.append("    id: ").append(toIndentedString(id)).append("\n");
        sb.append("    type: ").append(toIndentedString(type)).append("\n");
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
