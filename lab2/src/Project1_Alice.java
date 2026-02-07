import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.*;
import java.util.Base64;

public class Project1_Alice {
    private static final String KEY = "88888888"; 
    private static final String ID_A = "AliceClient";

    public static void main(String[] args) throws Exception {
        Socket socket = new Socket("localhost", 1234);
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());
        DataInputStream in = new DataInputStream(socket.getInputStream());

        SecretKeySpec secretKey = new SecretKeySpec(KEY.getBytes(), "DES");
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");

        // 1. Send Message 1: IDA || NA 
        String nonceA = "NA" + (int)(Math.random() * 1000);
        String msg1 = ID_A + "||" + nonceA; 
        out.writeUTF(msg1); //message with ID of Alice and nonce is sent to Bob
        System.out.println("Sent Message 1: " + msg1); //printed message

        // 2. Receive Message 2: NB || E(KAB, [IDB || NA]) [cite: 27, 54]
        String msg2 = in.readUTF(); //Alice receives message from Bob
        System.out.println("Received Message 2: " + msg2);
        String[] parts = msg2.split("\\|\\|");
        String nonceB = parts[0];
        String encryptedPart2 = parts[1];

        // Decrypt and Verify Message 2 
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decrypted2Bytes = cipher.doFinal(Base64.getDecoder().decode(encryptedPart2));
        String decrypted2 = new String(decrypted2Bytes);
        System.out.println("Decrypted Message 2: " + decrypted2);

        if (decrypted2.contains(nonceA)) {
            System.out.println("Bob Verified. Preparing Message 3...");

            // 3. Send Message 3: E(KAB, [IDA || NB]) 
            String dataToEncrypt3 = ID_A + "||" + nonceB;
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encrypted3 = cipher.doFinal(dataToEncrypt3.getBytes());
            String msg3 = Base64.getEncoder().encodeToString(encrypted3);
            out.writeUTF(msg3);
            System.out.println("Sent Message 3 (Encrypted): " + msg3);
        } else {
            System.out.println("Nonce A mismatch! Potential intruder.");
        }

        socket.close();
    }
}