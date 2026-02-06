package main;

/*
* COE 817 Lab 1 Project 1
* SiriServer
* Authors: Mukesh Sabesan, Kiana Lee
*/

import java.net.*;
import java.io.*;

public class SiriServer {
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
        String key = makeKey(str);
        str = str.toUpperCase();
        
         for(int i=0; i<str.length(); i++){
            if(str.charAt(i) >= 'A' && str.charAt(i) <= 'Z'){
                int x = (str.charAt(i) + key.charAt(i)) % 26; //formula to encrpyt message 
                x+= 'A'; //converts int to char, add val of x to A (65)
                encryptMsg += (char)(x);
            } else{
                encryptMsg += (char)(str.charAt(i));
            }
        }
        return encryptMsg;
    }

    static String decrypt(String str, String keyShort){
        String decryptMsg = "";
        String key = makeKey(str);
        str = str.toUpperCase();
        
        for(int i=0; i<str.length(); i++){
            if(str.charAt(i) >= 'A' && str.charAt(i) <= 'Z'){
                int x = (str.charAt(i) - key.charAt(i) + 26) % 26; //formula to encrpyt message 
                x+= 'A'; //converts int to char, add val of x to A (65)
                decryptMsg += (char)(x);
            } else{
                decryptMsg += (char)(str.charAt(i));
            }   
        }
        return decryptMsg;
    }

    public static void main(String[] args) throws IOException {
        
        if (args.length != 1) {
            System.err.println("Usage: java KnockKnockServer 4444");
            System.exit(1);
        }

        int portNumber = Integer.parseInt(args[0]);
            
        int clientNumber = 1;
            
        try (ServerSocket serverSocket = new ServerSocket(portNumber)){
            while(true){
                Socket clientSocket = serverSocket.accept();
                System.out.println("Client connected: " + clientSocket);
                new Thread(new ClientHandler(clientSocket, clientNumber)).start();
                clientNumber++;
            }
        }
        catch (IOException e) {
            System.out.println("Exception caught when trying to listen on port "
                + portNumber + " or listening for a connection");
            System.out.println(e.getMessage());
        }
    }
    
    static class ClientHandler implements Runnable{
        private final Socket socket;
        private final int clientNumber;
        
        ClientHandler(Socket socket, int clientNumber){
            this.socket = socket;
            this.clientNumber = clientNumber;
        }
        
        @Override
        public void run(){
             try(
                PrintWriter out =
                    new PrintWriter(socket.getOutputStream(), true);
                BufferedReader in = new BufferedReader(
                    new InputStreamReader(socket.getInputStream()));
            ) {
                String inputLine, outputLine;

                // Initiate conversation with client
                SiriProtocol kkp = new SiriProtocol();
                outputLine = kkp.processInput(null);
                String encPrompt = encrypt(outputLine, KEY);
                out.println(encPrompt);

                while ((inputLine = in.readLine()) != null) {
                    System.out.println("encrypted from client " + clientNumber + ": "+ inputLine);

                    String deMsg = decrypt(inputLine, KEY);
                    System.out.println("decrypted from client " + clientNumber + ": " + deMsg);

                    outputLine = kkp.processInput(deMsg);
                    String enMsg = encrypt(outputLine, KEY);
                    out.println(enMsg);
 
                    if (deMsg.equals("QUIT"))
                       System.out.println("Client " + clientNumber + " quit.");
                }
            } 
            catch (IOException e) {
                System.out.println("Client error: " + e.getMessage());
            } 
        }
    }
}
