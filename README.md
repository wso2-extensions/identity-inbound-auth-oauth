# identity-inbound-auth-oauth

## Building from the source

If you want to build **identity-inbound-auth-oauth** from the source code:

1. Install Java 11 (or Java 17)
2. Install Apache Maven 3.x.x (https://maven.apache.org/download.cgi#)
3. Get a clone or download the source from this repository (https://github.com/wso2-extensions/identity-inbound-auth-oauth)
4. Run the Maven command ``mvn clean install`` from the ``identity-inbound-auth-oauth`` directory.

### ℹ️ Important note for Mac (with Apple Silicon) users<br>
> 
> There are JDKs that target different types of architectures available to download for macOS. The test class `NTLMAuthenticationGrantHandlerTest` (in *components/org.wso2.carbon.identity.oauth/src/test/java/org/wso2/carbon/identity/oauth2/token/handlers/grant/iwa/ntlm/NTLMAuthenticationGrantHandlerTest.java*) will throw an UnsatisfiedLinkError if the installed JDK in your machine targets the aarch64 (ARM) architecture. Therefore, if you want to run the test class `NTLMAuthenticationGrantHandlerTest` please make sure that a JDK that targets x64 architecture is installed in your machine. 