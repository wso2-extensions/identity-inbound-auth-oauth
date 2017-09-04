package org.wso2.carbon.identity.oauth2.model;

import java.io.Serializable;

/**
 * This class is used to store http request header information
 */
public class HttpRequestHeader implements Serializable {

    private static final long serialVersionUID = 5419655486789962879L;

    private String name;
    private String[] values;

    /**
     * Instantiate a HTTPHeader object for the given name and values
     *
     * @param name    header name
     * @param values parameter values
     */
    public HttpRequestHeader(String name, String... values) {
        this.name = name;
        this.values = values;
    }

    /**
     * Returns the Header name
     *
     * @return header name
     */
    public String getName() {
        return name;
    }

    /**
     * Returns the header value
     *
     * @return header value
     */
    public String[] getValue() {
        return values;
    }

}
