package org.wso2.carbon.identity.oauth.par;

public class ValidateCallbackURLImpl implements ValidateCallbackURL {

//    private static final Logger LOGGER = Logger.getLogger(ValidateCallbackURL.class.getName());

    @Override
    public String validateCallbackURL(){
        return "I'm backend";
    }


    //    private static volatile ValidateCallbackURLImpl validateCallbackURL;

//    private  ValidateCallbackURLImpl() {
//    }
//
//    public static ValidateCallbackURLImpl getInstance() {
//
//        if (validateCallbackURL == null) {
//            synchronized (ValidateCallbackURLImpl.class) {
//                if (validateCallbackURL == null) {
//                    validateCallbackURL = new ValidateCallbackURLImpl();
//                }
//            }
//        }
//        return validateCallbackURL;
//    }

//    public void createGreetingCard(String cardName, String greeting) {
//        //Logic of creating a greeting card goes here.
//        GreetingCard greetingCard = new GreetingCard(cardName, greeting);
//        LOGGER.info("Created a greeting card " + greetingCard.getCardName() + " with greeting: "+ greetingCard.getGreeting());
//    }

//    public void listGreetingCards() {
//
//    }

}
