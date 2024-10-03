package org.wso2.carbon.identity.oauth2.fga;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import javax.validation.constraints.*;


import io.swagger.annotations.*;
import java.util.Objects;
import javax.validation.Valid;

public class AccessCheckRequestResource  {

    private String id;
    private String type;

    /**
     **/
    public AccessCheckRequestResource id(String id) {

        this.id = id;
        return this;
    }

    @ApiModelProperty(example = "resource456", value = "")
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
    public AccessCheckRequestResource type(String type) {

        this.type = type;
        return this;
    }

    @ApiModelProperty(example = "resource", value = "")
    @JsonProperty("type")
    @Valid
    public String getType() {
        return type;
    }
    public void setType(String type) {
        this.type = type;
    }



    @Override
    public boolean equals(java.lang.Object o) {

        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        AccessCheckRequestResource accessCheckRequestResource = (AccessCheckRequestResource) o;
        return Objects.equals(this.id, accessCheckRequestResource.id) &&
                Objects.equals(this.type, accessCheckRequestResource.type);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, type);
    }

    @Override
    public String toString() {

        StringBuilder sb = new StringBuilder();
        sb.append("class AccessCheckRequestResource {\n");

        sb.append("    id: ").append(toIndentedString(id)).append("\n");
        sb.append("    type: ").append(toIndentedString(type)).append("\n");
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