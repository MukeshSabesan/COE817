/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Other/File.java to edit this template
 */

/**
 * COE817 Lab 2
 * Authors: Kiana Lee and Mukesh Sabesan
 */

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashSet;


public class Project3_Bob {

    private static final String KEY = "88888888"; // 8-byte key for DES [cite: 24]
    private static final String ID_B = "BobServer";
    
    // method to read used Nonces from text file.
    private HashSet<String> getUsedNonces() {
        HashSet<String> usedNonces = new HashSet<>();
        try (BufferedReader reader = new BufferedReader(new FileReader("usedNonces.txt"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                usedNonces.add(line);  // Add each nonce to the HashSet
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return usedNonces;
    }
    
    
    public static void main(String args[]) throws Exception{
        Project3_Bob bob = new Project3_Bob();
        ServerSocket serverSocket = new ServerSocket(1234);
        System.out.println("Bob is waiting for Alice..." + "\n");
        Socket socket = serverSocket.accept(); //Bob is listening for Alice and accepts Alice's socket.

        DataInputStream in = new DataInputStream(socket.getInputStream());
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());
        
         // Create Public and Private Key Pairs for Bob
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        
        KeyPair kp = kpg.generateKeyPair();
        PublicKey bobPublicKey = kp.getPublic();
        PrivateKey bobPrivateKey = kp.getPrivate();
        
        // Bob receives Alice's Public Key length and Public Key (in bytes) after establishing connection
        int aliceKeyLen = in.readInt();
        byte[] alicePbKeyBytes = in.readNBytes(aliceKeyLen);
        
        //Decode the bytes from Alice's public Key into a public key object.
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(alicePbKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey alicePublicKey = keyFactory.generatePublic(keySpec);
        
        // Bob sends the length of her public key, followed by her public key after receiving Bob's public key
        byte[] bobPbKeyBytes = bobPublicKey.getEncoded();
        out.writeInt(bobPbKeyBytes.length);
        out.write(bobPbKeyBytes);
        
        // Enabling RSA Signature
        Signature signature = Signature.getInstance("SHA256withRSA");
        

        // 1. Receive Message 1: M || SignA(M)
        String msg1 = in.readUTF();
        System.out.println("Received Message 1 (Signed): " + msg1 + "\n");
        String[] parts = msg1.split("\\|\\|");
        String message = parts[0];
        String signMessage = parts[1];
        String nonceA = parts[2];
         
        //Decode signed message
        byte[] signedData = Base64.getDecoder().decode(signMessage);
        
        // Verify Signature using Alice's Public Key
        signature.initVerify(alicePublicKey);
        signature.update(message.getBytes(StandardCharsets.UTF_8));
        
        if(bob.isNonceUsed(nonceA)){ // if the nonce was used previously, then Bob will know it is a replay attack.
            System.out.println("Replay attack detected! This message has already been processed.");
        }else{
            // once nonce is verified, Bob will verify whether the message has been corrupted using its Signature.
            if (signature.verify(signedData)){
                System.out.println("Received Message 1: " + message);
                System.out.println("Signature verified, Alice is authenticated!");
                bob.markNonceAsUsed(nonceA);
            }
            else{ //if the signature verify fails, then the message has been corrupted.
                System.out.println("Signature verification failed! Message may be corrupted.");
            }
        }
        
        socket.close();
        serverSocket.close();
    }
    
    // method to check the nonce given by Alice (or "Alice") to see if it was used.
    private boolean isNonceUsed(String nonce) {
        // Read the list of used nonces from the text file
        HashSet<String> usedNonces = getUsedNonces();

        // Check if the received nonce is in the used nonces set
        if (usedNonces.contains(nonce)) {
            return true;  // Nonce has been used before, indicating a replay attack
        }
        return false;  // Nonce is new and valid
    }
    
    // method to store used Nonces in text file.
    private void markNonceAsUsed(String nonce) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter("usedNonces.txt", true))) {
            writer.write(nonce);  // Write the nonce
            writer.newLine();     // Add a new line after each nonce
        } catch (IOException e) {
            e.printStackTrace();
    }
        
    }
}
