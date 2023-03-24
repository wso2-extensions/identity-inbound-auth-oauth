package org.wso2.carbon.identity.oauth2.token.extension;

import com.google.gdata.client.authn.oauth.OAuthException;
import com.hazelcast.com.fasterxml.jackson.databind.ObjectMapper;
import jdk.nashorn.api.scripting.ClassFilter;
import jdk.nashorn.api.scripting.NashornScriptEngineFactory;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.AsyncReturn;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsLogger;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.oauth.extension.engine.JSBasedEngine;
import org.wso2.carbon.identity.oauth.extension.engine.JSBasedEngineImpl;
import org.wso2.carbon.identity.oauth.extension.functions.CallChoreoFunctionImpl;
import org.wso2.carbon.identity.oauth.extension.functions.Callback;
import org.wso2.carbon.identity.oauth.extension.functions.CallbackImpl;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.script.Bindings;
import javax.script.ScriptContext;
import javax.script.ScriptEngine;

public class JsExtensionBuilderFactory implements JsBaseExtensionBuilderFactory {

    private static final Log LOG = LogFactory.getLog(JsExtensionBuilderFactory.class);

    private static final String JS_BINDING_CURRENT_CONTEXT = "JS_BINDING_CURRENT_CONTEXT";
    private static final String[] NASHORN_ARGS = {"--no-java", "--no-deprecation-warning"};
    private static final String REMOVE_FUNCTIONS = "var quit=function(){Log.error('quit function is restricted.')};" +
            "var exit=function(){Log.error('exit function is restricted.')};" +
            "var print=function(){Log.error('print function is restricted.')};" +
            "var echo=function(){Log.error('echo function is restricted.')};" +
            "var readFully=function(){Log.error('readFully function is restricted.')};" +
            "var readLine=function(){Log.error('readLine function is restricted.')};" +
            "var load=function(){Log.error('load function is restricted.')};" +
            "var loadWithNewGlobal=function(){Log.error('loadWithNewGlobal function is restricted.')};" +
            "var $ARG=null;var $ENV=null;var $EXEC=null;" +
            "var $OPTIONS=null;var $OUT=null;var $ERR=null;var $EXIT=null;" +
            "Object.defineProperty(this, 'engine', {});";
    @SuppressWarnings("removal")
    private NashornScriptEngineFactory factory;
    private ClassFilter classFilter;
    @Override
    public void init() {

        factory = new NashornScriptEngineFactory();
    }

    private ClassLoader getClassLoader() {

        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        return classLoader == null ? NashornScriptEngineFactory.class.getClassLoader() : classLoader;
    }

    @Override
    public ScriptEngine createEngine() {

        ScriptEngine engine = factory.getScriptEngine(NASHORN_ARGS, getClassLoader());
        Bindings bindings = engine.createBindings();
        engine.setBindings(bindings, ScriptContext.GLOBAL_SCOPE);
        engine.setBindings(engine.createBindings(), ScriptContext.ENGINE_SCOPE);
        JsLogger jsLogger = new JsLogger();
        Person person = new Person("John", 25);
        engine.put("person", person);
        bindings.put(FrameworkConstants.JSAttributes.JS_LOG, jsLogger);
//        CallChoreoFunctionImpl callChoreoFunction = new CallChoreoFunctionImpl( "testasgardeo1");
//        bindings.put("CallChoreo", callChoreoFunction);
        return engine;
    }

    @Override
    public Object executeScript(ScriptEngine engine, String script) {

        try {
            // Define a sendError function in Java
            JSBasedEngine jsBasedEngine = JSBasedEngineImpl.getInstance();
            Person person = new Person("John", 25);
            ObjectMapper mapper = new ObjectMapper();
            Map<String, Object> pMap = mapper.convertValue(person, Map.class);
            Callback callback = new CallbackImpl(jsBasedEngine);
            JsLogger jsLogger = new JsLogger();
            CallChoreoFunctionImpl callChoreoFunction = new CallChoreoFunctionImpl( "testasgardeo1", callback);
            Map<String, Object> bindings = new HashMap<>();
            bindings.put("CallChoreo", callChoreoFunction);
            bindings.put(FrameworkConstants.JSAttributes.JS_LOG, jsLogger);
            List<String> a = new ArrayList<>();
            a.add("access_token");
            a.add("person");
            a.add("id_token");
            Map<String, Object> result = jsBasedEngine
                    .createEngine()
                    .addBindings(bindings)
                    .evalScript(script)
                    .invokeFunction("dynamicTokenData", pMap)
                    .getJSObjects(a);
            return result;
        } catch (Exception e) {
            LOG.error("Error while executing script", e);
        }

        return null;
    }

    /**
     * This method allows a BiConsumer which throws exceptions to be used in places which expects a BiConsumer.
     *
     * @param <T>         the type of the input to the function
     * @param <U>         the type of the input to the function
     * @param <V>         the type of the input to the function
     * @param <E>         the type of Exception
     * @param triConsumer instances of the {@code TriConsumerWithExceptions} functional interface
     * @return an instance of the {@code BiConsumer}
     */
    public static <T, U , V , E extends Exception> AsyncReturn rethrowTriConsumer(AsyncReturn triConsumer) {

        return (t, u, v) -> {
            try {
                triConsumer.accept(t, u, v);
            } catch (Exception exception) {
                throw new RuntimeException(exception);
            }
        };
    }

    class Person {
        private String name;
        private int age;

        public Person(String name, int age) {
            this.setName(name);
            this.age = age;
        }

        public String getName() {
            return name;
        }

        public int getAge() {
            return age;
        }

        public void setName(String name) {

            this.name = name;
        }
    }
}
