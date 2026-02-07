/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Other/File.java to edit this template
 */

/**
 * COE817 Lab 2
 * Authors: Kiana Lee and Mukesh Sabesan
 */

import javax.crypto.Cipher;
import java.io.*;
import java.net.*;
import java.security.KeyFactory;
import java.util.Base64;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Signature;



public class Project3_Attacker {
    private static final String KEY = "88888888"; 
    private static final String ID_A = "AliceClient";
    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) throws Exception{
        Socket socket = new Socket("localhost", 1234);
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());
        DataInputStream in = new DataInputStream(socket.getInputStream());
        
        // Create Public and Private RSA Keys for Alice
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        
        KeyPair kp = kpg.generateKeyPair();
        PublicKey alicePublicKey = kp.getPublic();
        PrivateKey alicePrivateKey = kp.getPrivate();
        
        // Enabling RSA Signatures
        Signature signature = Signature.getInstance("SHA256withRSA");
        
        // Alice sends the length of her public key, followed by her public key after establishing connection.
        byte[] alicePbKeyBytes = alicePublicKey.getEncoded();
        out.writeInt(alicePbKeyBytes.length);
        out.write(alicePbKeyBytes);
        
        // Alice receives Bob's Public Key
        int bobKeyLen = in.readInt();
        byte[] bobPbKeyBytes = in.readNBytes(bobKeyLen);
        
        //Decode the bytes from Bob's public Key into a public key object.
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(bobPbKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey bobPublicKey = keyFactory.generatePublic(keySpec);
        
        // This is precisely where the attack fails, the Attacker uses a previously used Nonce.
        String nonceA = "NA453";
        
        // 1. Send Message M || SigA(M)
        String message = "This is private info for you Bob, no one should know this";
        signature.initSign(alicePrivateKey);
        signature.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] signedMessage = signature.sign();
        String msg1 = message + "||" + Base64.getEncoder().encodeToString(signedMessage) + "||" + nonceA;
        out.writeUTF(msg1);
        System.out.println("Sent Message 1: " + msg1 + "\n"); //printed message


        socket.close();
    }
}
