package org.wso2.carbon.identity.oauth2.fga;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonCreator;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import javax.validation.constraints.*;


import io.swagger.annotations.*;
import java.util.Objects;
import javax.validation.Valid;
import javax.xml.bind.annotation.*;

public class GraphGenerationResponseResults  {

    private String objectType;
    private String objectId;

    /**
     **/
    public GraphGenerationResponseResults objectType(String objectType) {

        this.objectType = objectType;
        return this;
    }

    @ApiModelProperty(example = "user", value = "")
    @JsonProperty("object_type")
    @Valid
    public String getObjectType() {
        return objectType;
    }
    public void setObjectType(String objectType) {
        this.objectType = objectType;
    }

    /**
     **/
    public GraphGenerationResponseResults objectId(String objectId) {

        this.objectId = objectId;
        return this;
    }

    @ApiModelProperty(example = "jane@the-eyres.com", value = "")
    @JsonProperty("object_id")
    @Valid
    public String getObjectId() {
        return objectId;
    }
    public void setObjectId(String objectId) {
        this.objectId = objectId;
    }



    @Override
    public boolean equals(java.lang.Object o) {

        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        GraphGenerationResponseResults graphGenerationResponseResults = (GraphGenerationResponseResults) o;
        return Objects.equals(this.objectType, graphGenerationResponseResults.objectType) &&
                Objects.equals(this.objectId, graphGenerationResponseResults.objectId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(objectType, objectId);
    }

    @Override
    public String toString() {

        StringBuilder sb = new StringBuilder();
        sb.append("class GraphGenerationResponseResults {\n");

        sb.append("    objectType: ").append(toIndentedString(objectType)).append("\n");
        sb.append("    objectId: ").append(toIndentedString(objectId)).append("\n");
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
