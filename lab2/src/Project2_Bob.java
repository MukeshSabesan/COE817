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
import java.util.Base64;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;

public class Project2_Bob {

    private static final String KEY = "88888888"; // 8-byte key for DES [cite: 24]
    private static final String ID_B = "BobServer";
    
    public static void main(String args[]) throws Exception{
        ServerSocket serverSocket = new ServerSocket(1234);
        System.out.println("Bob is waiting for Alice...");
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
        
        // Enabling RSA Encryption
        Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");

        // 1. Receive Message 1: IDA || NA [cite: 26, 54]
        String msg1 = in.readUTF();
        System.out.println("Received Message 1: " + msg1 + "\n");
        String[] parts = msg1.split("\\|\\|");
        String nonceA = parts[1];

        // 2. Send Message 2: (E(PUA, E(PRB, NA)) || NB) [cite: 27, 54]
        String nonceB = "NB" + (int)(Math.random() * 1000);
        // E(PRB, NA) (Inner Encryption)
        cipher.init(Cipher.ENCRYPT_MODE, bobPrivateKey);
        byte[] innerEncrypt = cipher.doFinal(nonceA.getBytes());
        // E(PUA, E(PRB, NA)) (Full Encryption)
        cipher.init(Cipher.ENCRYPT_MODE, alicePublicKey);
        byte[] outerEncrypt = cipher.doFinal(innerEncrypt);   
        // Sending E(PUA, E(PRB, NA)) || NB) as msg2
        String msg2 = Base64.getEncoder().encodeToString(outerEncrypt) + "||" + nonceB;
        out.writeUTF(msg2);
        System.out.println("Sent Message 2: " + msg2 + "\n");

        // 3. Receive Message 3: E(PUB, E(PRA, NB)) [cite: 29, 56]
        String msg3 = in.readUTF();
        System.out.println("Received Message 3 (Encrypted): " + msg3 + "\n");

        // Decrypt and Verify Message 3 outer part: E(PUB, E(PRA, NB))
        cipher.init(Cipher.DECRYPT_MODE, bobPrivateKey);
        byte[] outerdecrypted3Bytes = cipher.doFinal(Base64.getDecoder().decode(msg3));
        String outerDecrypted = new String(outerdecrypted3Bytes);
        //System.out.println("Outer Decrypted Message 3: " + outerDecrypted);
        
        // Decrypt and Verify Message 3 inner part: E(PRA, NB)
        cipher.init(Cipher.DECRYPT_MODE, alicePublicKey);
        byte[] innerDecrypted3Bytes = cipher.doFinal(outerdecrypted3Bytes);
        String innerDecrypted = new String(innerDecrypted3Bytes);

        if (innerDecrypted.contains(nonceB)) {
            System.out.println("Decrypted message 3 contains Nonce B.");
            System.out.println("Authentication Successful: Alice is verified!");
        } else {
            System.out.println("Authentication Failed!");
        }

        socket.close();
        serverSocket.close();
    }
}
