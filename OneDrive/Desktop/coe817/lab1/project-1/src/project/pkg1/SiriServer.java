package project.pkg1;

/*
* COE 817 Lab 1 Project 1
* SiriServer
* Authors: Mukesh Sabesan, 
*/

import java.net.*;
import java.io.*;

public class SiriServer {
    public static void main(String[] args) throws IOException {
        
        if (args.length != 1) {
            System.err.println("Usage: java KnockKnockServer 4444");
            System.exit(1);
        }

        int portNumber = Integer.parseInt(args[0]);
        while(true){
            try ( 
                ServerSocket serverSocket = new ServerSocket(portNumber);
                Socket clientSocket = serverSocket.accept();
                PrintWriter out =
                    new PrintWriter(clientSocket.getOutputStream(), true);
                BufferedReader in = new BufferedReader(
                    new InputStreamReader(clientSocket.getInputStream()));
            ) {

                String inputLine, outputLine;

                // Initiate conversation with client
                SiriProtocol kkp = new SiriProtocol();
                outputLine = kkp.processInput(null);
                out.println(outputLine);

                while ((inputLine = in.readLine()) != null) {
                    outputLine = kkp.processInput(inputLine);
                    out.println(outputLine);
                    if (outputLine.equals("Bye."))
                       break;
                }
            } catch (IOException e) {
                System.out.println("Exception caught when trying to listen on port "
                    + portNumber + " or listening for a connection");
                System.out.println(e.getMessage());
            }
        }
    }
}
