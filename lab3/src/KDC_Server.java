import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Other/File.java to edit this template
 */

/**
 *
 * @author mukes
 */
public class KDC_Server {
    private static final String ID_K = "KDCServer";
    /**
     * @param args the command line arguments
     */
    private static final Map<String, String> masterKeys = new HashMap<>();
    private static final Map<String, DataOutputStream> clientOuts = new HashMap<>();
  
    public static void main(String args[]) throws Exception {
        // TODO code application logic here
        
        // generate keypair in main function, to be pass into each thread.
        // This way every client works with the same KDC server public and private key.
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
                
        int clientNumber = 1;
            
        try (ServerSocket serverSocket = new ServerSocket(1234)){
            System.out.println("KDC Server is up and running... \n");
            while(true){
                Socket clientSocket = serverSocket.accept();
                System.out.println("Client connected: " + clientSocket);
                new Thread(new ClientHandler(clientSocket, clientNumber, kp)).start();
                clientNumber++;
            }
        }
        catch (IOException e) {
            System.out.println("Exception caught when trying to listen on port or listening for a connection");
            System.out.println(e.getMessage());
        }
    }
    
     static class ClientHandler implements Runnable{
        private final Socket socket;
        private final int clientNumber;
        private final KeyPair kp;
        
        ClientHandler(Socket socket, int clientNumber, KeyPair kp){
            this.socket = socket;
            this.clientNumber = clientNumber;
            this.kp = kp;
        }
        
        @Override
        public void run(){
             try(
                DataInputStream in = new DataInputStream(socket.getInputStream());
                DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            ) {
                String inputLine, outputLine;
                Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");
                 
                PublicKey kdcPublicKey = kp.getPublic();
                PrivateKey kdcPrivateKey = kp.getPrivate();
                // Initiate conversation with client
                // KDC server receives the Clients public key
                int clientKeyLen = in.readInt();
                byte[] clientPbKeyBytes = in.readNBytes(clientKeyLen);

                //Decode the bytes from Clients's public Key into a public key object.
                X509EncodedKeySpec keySpec = new X509EncodedKeySpec(clientPbKeyBytes);
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                PublicKey clientPublicKey = keyFactory.generatePublic(keySpec);
                
                 // KDC sends the length of their public key, followed by their public key after receiving the Client's public key
                byte[] kdcPbKeyBytes = kdcPublicKey.getEncoded();
                out.writeInt(kdcPbKeyBytes.length);
                out.write(kdcPbKeyBytes);
                
                String clientID = in.readUTF();
                System.out.println("Client Hosted, ID: " + clientID + "\n");
                
                // Send Message 1: E(PU_Client, [NK1|| IDK]),  KDC sends a nonce and its ID to the client.
                String nonceK = "NK" + (int)(Math.random() * 1000);
                String msg1 = nonceK + "||" + ID_K;
                // Encrypt the message
                cipher.init(Cipher.ENCRYPT_MODE, clientPublicKey);
                byte[] msg1Encrypt = cipher.doFinal(msg1.getBytes());
                String msg1Final = Base64.getEncoder().encodeToString(msg1Encrypt);
                out.writeUTF(msg1Final);
                System.out.println("Sent Message 1 to " + clientID + ": " + msg1Final + "\n");
             
                
                // Receive Message 2: E(PUK, [N_Client|| NK]) from Client
                String msg2 = in.readUTF();
                System.out.println("Received Message 2 (Encrypted) from " + clientID + ": " + msg2 + "\n");
                cipher.init(Cipher.DECRYPT_MODE, kdcPrivateKey);
                byte[] decrypted2Bytes = cipher.doFinal(Base64.getDecoder().decode(msg2));
                String decrypted2 = new String(decrypted2Bytes);
                System.out.println("Decrypted Message 2 from " + clientID + ": " + decrypted2);
                
                String[] parts = decrypted2.split("\\|\\|");
                String nonceA = parts[0];
                String nonceK_received = parts[1];
                
                if (decrypted2.contains(nonceK)) {
                    System.out.println("Decrypted message 2 from " + clientID + " contains Nonce K. \n");
                    System.out.println("Authentication Successful: " + clientID + " is verified!");
                } else {
                    System.out.println("Authentication Failed!");
                    socket.close();
                    return;
                }
                
                // Send Message 3: E(PU_Client, NK),  KDC sends its received Nonce back, to verify that there was no corruption.
                // Encrypt the message
                cipher.init(Cipher.ENCRYPT_MODE, clientPublicKey);
                byte[] msg3Encrypt = cipher.doFinal(nonceK_received.getBytes());
                String msg3Final = Base64.getEncoder().encodeToString(msg3Encrypt);
                out.writeUTF(msg3Final);
                System.out.println("Sent Message 3 to " + clientID + ": " + msg3Final + "\n");
                
                // Send Message 4: E(PU_Client, E(PRK, K_Client)),  KDC sends its received Nonce back, to verify that there was no corruption.
                // Encrypt the message
                String MasterKeyClient = "MK" + (int)(Math.random() * 1000);
                // Inner Encryption: E(PRK, K_Client)
                cipher.init(Cipher.ENCRYPT_MODE, kdcPrivateKey);
                byte[] innerEncrypt = cipher.doFinal(MasterKeyClient.getBytes());
                // Outer Encryption: E(PU_Client, E(PRK, K_Client)
                cipher.init(Cipher.ENCRYPT_MODE, clientPublicKey);
                byte[] msg4Encrypt = cipher.doFinal(innerEncrypt);
                String msg4Final = Base64.getEncoder().encodeToString(msg4Encrypt);
                out.writeUTF(msg4Final);
                System.out.println("Sent Message 4 to " + clientID + ": " + msg4Final + "\n");
                
                synchronized (masterKeys) {
                    masterKeys.put(clientID, MasterKeyClient);
                    clientOuts.put(clientID,out);
                    masterKeys.notifyAll();
                }

                System.out.println("[Phase 1] complete for " + clientID + " Master Key = " + MasterKeyClient + "\n");
               
                
                // PHASE 2 (Starts from here)
                System.out.println("=== Phase 2 Starting ===\n");

                if (clientID.equals("Client A")) {
                    // Receive IDA and IDB from Client A
                    String rcvIDA = in.readUTF();
                    String rcvIDB = in.readUTF();
                    System.out.println("[Phase 2] KDC received IDA=" + rcvIDA
                            + ", IDB=" + rcvIDB + " from Client A\n");

                    // Wait until Client B's master key is also available
                    synchronized (masterKeys) {
                        while (!masterKeys.containsKey("Client B")) {
                            try {
                                masterKeys.wait();
                            } catch (InterruptedException ex) {
                                Thread.currentThread().interrupt(); 
                                System.out.println("[Phase 2] Wait interrupted.");
                            }
                        }
}

                    String kaStr = masterKeys.get("Client A");
                    String kbStr = masterKeys.get("Client B");

                    // Generate session key KAB
                    String KAB = "KAB" + (int) (Math.random() * 10000);
                    System.out.println("[Phase 2] Generated session key KAB = " + KAB);

                    // Send E(KA, [KAB || IDB]) to Client A
                    String msgForA = KAB + "||" + rcvIDB;
                    String encMsgForA = simEncrypt(kaStr, msgForA);
                    out.writeUTF(encMsgForA);
                    System.out.println("[Phase 2] Sent E(KA, [KAB, IDB]) to Client A\n");

                    // Send E(KB, [KAB || IDA]) to Client B via B's stored output stream
                    String msgForB = KAB + "||" + rcvIDA;
                    String encMsgForB = simEncrypt(kbStr, msgForB);
                    synchronized (clientOuts) {
                        DataOutputStream outB = clientOuts.get("Client B");
                        outB.writeUTF(encMsgForB);
                        outB.flush();
                    }
                    System.out.println("[Phase 2] Sent E(KB, [KAB, IDA]) to Client B\n");
                    System.out.println("[Phase 2] KDC Phase 2 complete. Session key distributed.");

                } else {
                     // Client B: hold socket open until Client A's thread pushes the message
                    System.out.println("[Phase 2] KDC holding Client B connection open...");
                    synchronized (masterKeys) {
                        while (!masterKeys.containsKey("Phase2Done")) {
                            try {
                                masterKeys.wait(10000);
                            } catch (InterruptedException ex) {
                                Thread.currentThread().interrupt();
                                System.out.println("[Phase 2] Wait interrupted.");
                            }
                        }
                    }
                    System.out.println("[Phase 2] Session key pushed to Client B. Done.");
    
                }
             }
                
            catch (IOException e) {
                System.out.println("Client error: " + e.getMessage());
            } catch (NoSuchAlgorithmException ex) {
                Logger.getLogger(KDC_Server.class.getName()).log(Level.SEVERE, null, ex);
            } catch (InvalidKeySpecException ex) {
                Logger.getLogger(KDC_Server.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IllegalBlockSizeException ex) {
                Logger.getLogger(KDC_Server.class.getName()).log(Level.SEVERE, null, ex);
            } catch (BadPaddingException ex) {
                Logger.getLogger(KDC_Server.class.getName()).log(Level.SEVERE, null, ex);
            } catch (InvalidKeyException ex) {
                Logger.getLogger(KDC_Server.class.getName()).log(Level.SEVERE, null, ex);
            } catch (NoSuchPaddingException ex) {
                Logger.getLogger(KDC_Server.class.getName()).log(Level.SEVERE, null, ex);
            } 
        }
    }
    // Symmetric encryption helper 
    static String simEncrypt(String key, String plaintext) {
        return "ENC[" + key + "]:" + plaintext;
    }

    static String simDecrypt(String key, String ciphertext) {
        String prefix = "ENC[" + key + "]:";
        if (ciphertext.startsWith(prefix)) {
            return ciphertext.substring(prefix.length());
        }
        throw new IllegalArgumentException("Decryption failed: wrong key or corrupted message.");
    }
}
