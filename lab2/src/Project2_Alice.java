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
import java.security.KeyFactory;
import java.util.Base64;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

public class Project2_Alice {
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
        
        // Enabling RSA Encryption
        Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");
        
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

        // 1. Send Message 1: IDA || NA 
        String nonceA = "NA" + (int)(Math.random() * 1000);
        String msg1 = ID_A + "||" + nonceA; 
        out.writeUTF(msg1); //message with ID of Alice and nonce is sent to Bob
        System.out.println("Sent Message 1: " + msg1 + "\n"); //printed message

        // 2. Receive Message 2: (E(PUA, E(PRB, NA)) || NB) 
        String msg2 = in.readUTF(); //Alice receives message from Bob
        System.out.println("Received Message 2: " + msg2 + "\n");
        String[] parts = msg2.split("\\|\\|");
        String encryptedPart2 = parts[0];
        String nonceB = parts[1];

        // Decrypt and Verify Message 2 outer portion (E(PUA, E(PRB, NA))
        cipher.init(Cipher.DECRYPT_MODE, alicePrivateKey);
        byte[] outerDecrypted2Bytes = cipher.doFinal(Base64.getDecoder().decode(encryptedPart2));
        String outerDecrypted = new String(outerDecrypted2Bytes);
        // System.out.println("Outer Decrypted Message 2 (E(PUA, E(PRB, NA)): " + outerDecrypted);
        
        // Decrypt and Verify inner Message within Message 2: E(PRB, NA)
        cipher.init(Cipher.DECRYPT_MODE, bobPublicKey);
        byte[] innerDecrypted2Bytes = cipher.doFinal(outerDecrypted2Bytes);
        String innerDecrypted = new String(innerDecrypted2Bytes);
        
        // Bob's identity is verified by figuring out whether the inner encrypted message contains the Nonce of Alice.
        if (innerDecrypted.contains(nonceA)) {
            System.out.println("Decrypted message 2 contains Nonce A.");
            System.out.println("Bob Verified. Preparing Message 3..." +  "\n");

            // 3. Send Message 3: E(PUB, E(PRA, NB)) 
            // E(PRA, NB) (Inner Encryption)
            cipher.init(Cipher.ENCRYPT_MODE, alicePrivateKey);
            byte[] innerEncrypt = cipher.doFinal(nonceB.getBytes());
            // E(PUB, E(PRA, NB)) (Full Encryption)
            cipher.init(Cipher.ENCRYPT_MODE, bobPublicKey);
            byte[] outerEncrypt = cipher.doFinal(innerEncrypt);
            // Sending E(PUB, E(PRA, NB)) as msg3
            String msg3 = Base64.getEncoder().encodeToString(outerEncrypt);
            out.writeUTF(msg3);
            System.out.println("Sent Message 3 (Encrypted): " + msg3);
        } else {
            System.out.println("Nonce A mismatch! Potential intruder.");
        }

        socket.close();
    }
}
