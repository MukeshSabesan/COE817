
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;

/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Other/File.java to edit this template
 */

/**
 *
 * @author mukes
 */
public class Client_B {

    /**
     * @param args the command line arguments
     */
    
    private static final String ID_B = "Client B";
    public static void main(String args[]) throws Exception {
        Socket socket = new Socket("localhost", 1234);
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());
        DataInputStream in = new DataInputStream(socket.getInputStream());
        
        // Create Public and Private RSA Keys for Client B
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        
        KeyPair kp = kpg.generateKeyPair();
        PublicKey publicKeyB = kp.getPublic();
        PrivateKey privateKeyB = kp.getPrivate();
        
        // Enabling RSA Encryption
        Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");
        
        // Client B sends the length of their public key, followed by their public key after establishing connection.
        byte[] bPbKeyBytes = publicKeyB.getEncoded();
        out.writeInt(bPbKeyBytes.length);
        out.write(bPbKeyBytes);
        
        // Client B receives KDC Server's public key
        int kdcKeyLen = in.readInt();
        byte[] kdcPbKeyBytes = in.readNBytes(kdcKeyLen);
        
        //Decode the bytes from Bob's public Key into a public key object.
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(kdcPbKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey kdcPublicKey = keyFactory.generatePublic(keySpec);
        
        // 1. B sends their ID (ID_B) to KDC Server
        out.writeUTF(ID_B);
        
        // Receive Message 1: E(PUB, [NK1|| IDK])
        String msg1 = in.readUTF();
        System.out.println("Received Message 1 (Encrypted): " + msg1);
        cipher.init(Cipher.DECRYPT_MODE, privateKeyB);
        byte[] decrypted1Bytes = cipher.doFinal(Base64.getDecoder().decode(msg1));
        String decrypted1 = new String(decrypted1Bytes);
        System.out.println("Decrypted Message 1: " + decrypted1);
        
        // Split the message and store the nonce and the ID.
        String[] parts = decrypted1.split("\\|\\|");
        String nonceK = parts[0];
        String ID_K = parts[1];
        
        // Send Message 2: E(PUK, [NB|| NK2]),  Client B sends its nonce and the nonce of KDC given.
        String nonceB = "NB" + (int)(Math.random() * 1000);
        String msg2 = nonceB + "||" + nonceK;
        // Encrypt the message
        cipher.init(Cipher.ENCRYPT_MODE, kdcPublicKey);
        byte[] msg2Encrypt = cipher.doFinal(msg2.getBytes());
        String msg2Final = Base64.getEncoder().encodeToString(msg2Encrypt);
        out.writeUTF(msg2Final);
        System.out.println("Sent Message 2: " + msg2Final + "\n");
        
         // Receive Message 3: E(PUA, NK1)
        String msg3 = in.readUTF();
        System.out.println("Received Message 3 (Encrypted): " + msg3);
        cipher.init(Cipher.DECRYPT_MODE, privateKeyB);
        byte[] decrypted3Bytes = cipher.doFinal(Base64.getDecoder().decode(msg3));
        String nonceK_check = new String(decrypted3Bytes);
        System.out.println("Decrypted Message 3: " + nonceK_check);
        
        if (nonceK_check.contains(nonceK)) {
            System.out.println("Nonce K verified from KDC Server.");
        } else {
            System.out.println("Nonce was possibly corrupted. Closing connection");
            socket.close();
        }
        
        // Decrypt Message 4 outer part: E(PUB, E(PRK, KB))
        String msg4 = in.readUTF();
        cipher.init(Cipher.DECRYPT_MODE, privateKeyB);
        byte[] outerdecrypted4Bytes = cipher.doFinal(Base64.getDecoder().decode(msg4));
        
        // Decrypt Message 4 inner part: E(PRK, KB)
        cipher.init(Cipher.DECRYPT_MODE, kdcPublicKey);
        byte[] innerDecrypted3Bytes = cipher.doFinal(outerdecrypted4Bytes);
        // Master Key received from KDC Server
        String masterKey = new String(innerDecrypted3Bytes, StandardCharsets.UTF_8).replace("\0", "").trim();
        System.out.println("Decrypted Message 4: " + masterKey + "\n");
        
        // PHASE 2 (Starts from here)
        System.out.println("=== Phase 2: Client B waiting for session key from KDC... ===\n");

        // Receive E(KB, [KAB || IDA]) from KDC
        String encMsg = in.readUTF();
        System.out.println("Received from KDC (Encrypted): " + encMsg);

        // Decrypt using master key KB
        String decrypted     = KDC_Server.simDecrypt(masterKey, encMsg);
        System.out.println("Decrypted: " + decrypted);

        String[] phase2Parts = decrypted.split("\\|\\|");
        String   KAB         = phase2Parts[0];
        String   receivedIDA = phase2Parts[1];

        System.out.println("Session Key KAB = " + KAB);
        System.out.println("Received IDA    = " + receivedIDA);

        // Verify IDA
        if (receivedIDA.equals("Client A")) {
            System.out.println("IDA verified. Session key KAB is trusted.\n");
        } else {
            System.out.println("WARNING: IDA mismatch! Possible replay/tampering attack.\n");
        }

        System.out.println("=== Phase 2 Complete. Client B holds session key KAB = " + KAB + " ===");

        socket.close();
        
    }
}
