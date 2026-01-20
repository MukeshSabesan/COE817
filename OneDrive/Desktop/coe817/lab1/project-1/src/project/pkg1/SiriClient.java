package project.pkg1;
/*
* COE 817 Lab 1 Project 1
* SiriClient
* Authors: Mukesh Sabesan, 
*/
 
import java.io.*;
import java.net.*;


public class SiriClient {
    static final String KEY = "TMU";

    //repeats key so it is same length as input
    static String makeKey(String str){
        String keyMod = KEY;
        int keyLength = KEY.length();
        //
        for(int i=0;keyMod.length()< str.length(); i++){
            int place = i % keyLength; //makes it so place cycles thru 0,1,2
            keyMod+=(KEY.charAt(place));

        }
        return keyMod;
    }
    static String encrypt(String str, String keyShort){
        String encryptMsg = "";
        String key = makeKey(keyShort);
        str = str.toUpperCase();
        for(int i=0; i<str.length(); i++){
            int x = (str.charAt(i) + key.charAt(i)) % 26; //formula to encrpyt message 

            x+= 'A'; //converts int to char, add val of x to A (65)
            encryptMsg += (char)(x);
        }
        return encryptMsg;
    }

    static String decrypt(String str, String keyShort){
        String decryptMsg = "";
        string key = makeKey(keyShort);

        str = str.toUpperCase();
        for(int i=0; i<str.length(); i++){
            int x = (str.charAt(i) - key.charAt(i) + 26) % 26; //formula to encrpyt message 

            x+= 'A'; //converts int to char, add val of x to A (65)
            decryptMsg += (char)(x);
        }
        return decryptMsg;
    }

    

    public static void main(String[] args) throws IOException {
         
        if (args.length != 2) {
            System.err.println(
                "Usage: java EchoClient <host name> <port number>");
            System.exit(1);
        }
 
        String hostName = args[0];
        int portNumber = Integer.parseInt(args[1]);
 
        try (
            Socket kkSocket = new Socket(hostName, portNumber);
            PrintWriter out = new PrintWriter(kkSocket.getOutputStream(), true);
            BufferedReader in = new BufferedReader(
                new InputStreamReader(kkSocket.getInputStream()));
        ) {
            BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
            String fromServer = "";
            String fromUser ="";
            String key;


 
            while ((fromServer = in.readLine()) != null) {
                System.out.println("Encrypted Server Msg: " + fromServer);
                //-----------decrypt server------------------------------------
                String decString = decrypt(fromServer, KEY); //encrpyt message with key of same length
                System.out.println("Decrypted Server Msg:" + decString);

                if (fromServer.equals("Bye."))
                    break;
                 
                //get input
                fromUser = stdIn.readLine();
                //send input to server 
                if (fromUser != null) {
                    System.out.println("Client: " + fromUser);
                    //-----------encrypt client------------------------------------
                    String encString = encrypt(fromUser, KEY); //encrpyt message with key of same length
                    out.println(encString);
                }

                
            }
        } catch (UnknownHostException e) {
            System.err.println("Don't know about host " + hostName);
            System.exit(1);
        } catch (IOException e) {
            System.err.println("Couldn't get I/O for the connection to " +
                hostName);
            System.exit(1);
        }
    }
}