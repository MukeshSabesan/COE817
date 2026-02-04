import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.*;
import java.util.Base64;

public class Project1_Bob {
    private static final String KEY = "88888888"; // 8-byte key for DES [cite: 24]
    private static final String ID_B = "BobServer";

    public static void main(String[] args) throws Exception {
        ServerSocket serverSocket = new ServerSocket(1234);
        System.out.println("Bob is waiting for Alice...");
        Socket socket = serverSocket.accept();

        DataInputStream in = new DataInputStream(socket.getInputStream());
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());
        SecretKeySpec secretKey = new SecretKeySpec(KEY.getBytes(), "DES");
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");

        // 1. Receive Message 1: IDA || NA [cite: 26, 54]
        String msg1 = in.readUTF();
        System.out.println("Received Message 1: " + msg1);
        String[] parts = msg1.split("\\|\\|");
        String nonceA = parts[1];

        // 2. Send Message 2: NB || E(KAB, [IDB || NA]) [cite: 27, 54]
        String nonceB = "NB" + (int)(Math.random() * 1000);
        String dataToEncrypt2 = ID_B + "||" + nonceA;
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encrypted2 = cipher.doFinal(dataToEncrypt2.getBytes());
        String msg2 = nonceB + "||" + Base64.getEncoder().encodeToString(encrypted2);
        out.writeUTF(msg2);
        System.out.println("Sent Message 2: " + msg2);

        // 3. Receive Message 3: E(KAB, [IDA || NB]) [cite: 29, 56]
        String msg3 = in.readUTF();
        System.out.println("Received Message 3 (Encrypted): " + msg3);

        // Decrypt and Verify Message 3 [cite: 57]
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decrypted3Bytes = cipher.doFinal(Base64.getDecoder().decode(msg3));
        String decrypted3 = new String(decrypted3Bytes);
        System.out.println("Decrypted Message 3: " + decrypted3);

        if (decrypted3.contains(nonceB)) {
            System.out.println("Authentication Successful: Alice is verified!");
        } else {
            System.out.println("Authentication Failed!");
        }

        socket.close();
        serverSocket.close();
    }
}