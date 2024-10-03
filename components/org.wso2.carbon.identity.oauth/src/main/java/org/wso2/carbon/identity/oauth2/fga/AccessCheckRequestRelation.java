package org.wso2.carbon.identity.oauth2.fga;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import javax.validation.constraints.*;


import io.swagger.annotations.*;
import java.util.Objects;
import javax.validation.Valid;

public class AccessCheckRequestRelation  {

    private String method;

    /**
     **/
    public AccessCheckRequestRelation method(String method) {

        this.method = method;
        return this;
    }

    @ApiModelProperty(example = "GET", value = "")
    @JsonProperty("method")
    @Valid
    public String getMethod() {
        return method;
    }
    public void setMethod(String method) {
        this.method = method;
    }



    @Override
    public boolean equals(java.lang.Object o) {

        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        AccessCheckRequestRelation accessCheckRequestRelation = (AccessCheckRequestRelation) o;
        return Objects.equals(this.method, accessCheckRequestRelation.method);
    }

    @Override
    public int hashCode() {
        return Objects.hash(method);
    }

    @Override
    public String toString() {

        StringBuilder sb = new StringBuilder();
        sb.append("class AccessCheckRequestRelation {\n");

        sb.append("    method: ").append(toIndentedString(method)).append("\n");
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
