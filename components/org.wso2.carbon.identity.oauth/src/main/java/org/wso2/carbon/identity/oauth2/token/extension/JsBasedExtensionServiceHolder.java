package org.wso2.carbon.identity.oauth2.token.extension;

public class JsBasedExtensionServiceHolder {

    private static JsBasedExtensionServiceHolder instance = new JsBasedExtensionServiceHolder();
    private JsBasedExtensionService jsBasedExtensionService;

    public static JsBasedExtensionServiceHolder getInstance() {

        return instance;
    }

    public JsBasedExtensionService getJsBasedExtensionService() {

        return jsBasedExtensionService;
    }

    public void setJsBasedExtensionService(JsBasedExtensionService jsBasedExtensionService) {

        this.jsBasedExtensionService = jsBasedExtensionService;
    }

}
