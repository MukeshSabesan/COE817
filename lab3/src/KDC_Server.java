
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
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
                System.out.println("Sent Message 3: " + clientID + ": " + msg1Final + "\n");
             
                
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
                }
                
                // Send Message 3: E(PU_Client, NK),  KDC sends its received Nonce back, to verify that there was no corruption.
                // Encrypt the message
                cipher.init(Cipher.ENCRYPT_MODE, clientPublicKey);
                byte[] msg3Encrypt = cipher.doFinal(nonceK_received.getBytes());
                String msg3Final = Base64.getEncoder().encodeToString(msg3Encrypt);
                out.writeUTF(msg3Final);
                System.out.println("Sent Message 3: " + clientID + ": " + msg3Final + "\n");
                
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
                
                // PHASE 2 (Starts from here)
                
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
}
