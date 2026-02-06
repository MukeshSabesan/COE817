package project.pkg1;
/*
* COE 817 Lab 1 Project 1
* SiriServer
* Authors: Mukesh Sabesan, Kiana Lee
*/


public class SiriProtocol {
    private static final int STARTUP = 0;
    private static final int QUESTIONASKED = 1;

    private int state = STARTUP;
 
    public String processInput(String theInput) {
        String theOutput = null;
        
            if (state == STARTUP) {
                theOutput = "Welcome! I am Siri, ask anything!";
                state = QUESTIONASKED;
            } else if (state == QUESTIONASKED) {
                if (theInput.equalsIgnoreCase("Who created you?")) {
                    theOutput = "I was created by Apple.";
                } else if (theInput.equalsIgnoreCase("What does Siri mean?")){
                    theOutput = "victory and beautiful";
                }else if (theInput.toLowerCase().contains("are you")){
                    theOutput = "I am a virtual assistant.";
                }else if (theInput.equalsIgnoreCase("Who founded Apple?")){
                    theOutput = "Apple was founded by Steve Jobs, Steve Wozniak, and Ronald Wayne on April 1, 1976.";
                }else if (theInput.equalsIgnoreCase("Quit")){
                    theOutput = "Bye.";
                }
                else if (theInput.equalsIgnoreCase("hello") || theInput.equalsIgnoreCase("hi") || theInput.equalsIgnoreCase("hey")){
                    theOutput = "Welcome! I am Siri, ask anything!";
                }
                else{
                    theOutput = "I'm not programmed to answer that. Please ask chatgpt or other AI.";
                }
            }
            return theOutput;
    }
}