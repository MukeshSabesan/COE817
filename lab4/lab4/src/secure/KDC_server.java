package secure;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
/*
    certain blocks grabbed from lab 3 code 
*/

public class KDC_server {

    private static final String ID_K = "KDCServer";

    // Shared across client threads
    private static final Map<String, String>           masterKeys  = new HashMap<>();
    private static final Map<String, DataOutputStream> clientOuts  = new HashMap<>();
    private static final Map<String, PublicKey>        clientPubKeys = new HashMap<>();

    // Session Key
    private static SecretKey groupKeyKs;


    public static void main(String[] args) throws Exception {

        // Generate KDC RSA key pair (shared across all client handlers)
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        // Generate the AES-128 group session key Ks ONCE
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(128);
        groupKeyKs = kg.generateKey();
        System.out.println("KDC group key generated.");

        int clientNumber = 1;

        try (ServerSocket serverSocket = new ServerSocket(1234)) {
            System.out.println("KDC Server is up and running on...\n");
            while (true) {
                Socket clientSocket = serverSocket.accept();
                System.out.println("Client connected: " + clientSocket);
                new Thread(new ClientHandler(clientSocket, clientNumber, kp)).start();
                clientNumber++;
            }
        } catch (IOException e) {
            System.out.println("Exception: " + e.getMessage());
        }
    }

    // --------------------------------------------------------------------------------------
    //  CLIENT HANDLER
    // --------------------------------------------------------------------------------------
    static class ClientHandler implements Runnable {
        private final Socket socket;
        private final int clientNumber;
        private final KeyPair kp;

        ClientHandler(Socket socket, int clientNumber, KeyPair kp) {
            this.socket = socket;
            this.clientNumber = clientNumber;
            this.kp = kp;
        }

        @Override
        public void run() {
            try (
                DataInputStream  in  = new DataInputStream(socket.getInputStream());
                DataOutputStream out = new DataOutputStream(socket.getOutputStream())
            ) {
                PublicKey kdcPublicKey  = kp.getPublic();
                PrivateKey kdcPrivateKey = kp.getPrivate();
                Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");

                // Receive client's public key
                int clientKeyLen = in.readInt();
                byte[] clientPbKeyBytes = in.readNBytes(clientKeyLen);
                
                //Decode the bytes from Clients's public Key into a public key object.
                X509EncodedKeySpec keySpec = new X509EncodedKeySpec(clientPbKeyBytes);
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                PublicKey clientPublicKey = keyFactory.generatePublic(keySpec);

                // Send KDC's public key length and key 
                byte[] kdcPbKeyBytes = kdcPublicKey.getEncoded();
                out.writeInt(kdcPbKeyBytes.length);
                out.write(kdcPbKeyBytes);

                // Receive client ID
                String clientID = in.readUTF();
                System.out.println("Client connected, ID: " + clientID);

                // Message 1: E(PU_Client, [NK1 || IDK])
                String nonceK = "NK" + (int)(Math.random() * 1000);
                String msg1 = nonceK + "||" + ID_K;
                cipher.init(Cipher.ENCRYPT_MODE, clientPublicKey);
                byte[] msg1Encrypt = cipher.doFinal(msg1.getBytes());
                out.writeUTF(Base64.getEncoder().encodeToString(msg1Encrypt));
                System.out.println("KDC Sent Message 1 to " + clientID);

                // Message 2: Receive E(PU_KDC, [N_Client || NK])
                String msg2 = in.readUTF();
                cipher.init(Cipher.DECRYPT_MODE, kdcPrivateKey);
                String decrypted2 = new String(cipher.doFinal(Base64.getDecoder().decode(msg2))).replace("\0","").trim();;
                String[] parts = decrypted2.split("\\|\\|");
                String nonceA          = parts[0];
                String nonceK_received = parts[1];

                if (decrypted2.contains(nonceK)) {
                    System.out.println("Decrypted Message 2 from " + clientID + " contains Nonce K" );
                    System.out.println("Authentication successsful for " + clientID);
                }else{
                    System.out.println("authentication failed");
                    socket.close();
                    return;
                }
                System.out.println("KDC" + clientID + " authenticated");

                // Message 3: E(PU_Client, NK) - echo nonce
                cipher.init(Cipher.ENCRYPT_MODE, clientPublicKey);
                byte[] msg3Encrypt = cipher.doFinal(nonceK_received.getBytes());
                out.writeUTF(Base64.getEncoder().encodeToString(msg3Encrypt));
                System.out.println("Sent Message 3 to " + clientID);

                // Message 4: E(PU_Client, E(PR_KDC, MasterKey))
                String masterKey = "MK" + (int)(Math.random() * 10000);
                cipher.init(Cipher.ENCRYPT_MODE, kdcPrivateKey);
                byte[] innerEncrypt = cipher.doFinal(masterKey.getBytes());
                cipher.init(Cipher.ENCRYPT_MODE, clientPublicKey);
                byte[] msg4Encrypt = cipher.doFinal(innerEncrypt);
                out.writeUTF(Base64.getEncoder().encodeToString(msg4Encrypt));
                System.out.println("Sent Message 4 (master key) to " + clientID);

                // Store client info
                synchronized (masterKeys) {
                    masterKeys.put(clientID, masterKey);
                    clientOuts.put(clientID, out);
                    clientPubKeys.put(clientID, clientPublicKey);
                    masterKeys.notifyAll();
                }
                System.out.println("Verified Client " + clientID + "\n");

                // ── Distribute Group Key Ks ────────────────────────────
                System.out.println("Distributing group key to " + clientID);

                // Encrypt Ks with the client's master key (symmetric) 
                // Protocol: E(K_Client, [Ks || ID_KDC])
                String ksB64    = Base64.getEncoder().encodeToString(groupKeyKs.getEncoded());
                String phase2Msg = ksB64 + "||" + ID_K;
                String encPhase2 = simEncrypt(masterKey, phase2Msg);
                out.writeUTF(encPhase2);
                out.flush();
                System.out.println("Ks sent to " + clientID + " \n");
                
                //recieve client public key
                int ltPubLen   = in.readInt();
                byte[] ltPubBytes = in.readNBytes(ltPubLen);
                X509EncodedKeySpec ltSpec = new X509EncodedKeySpec(ltPubBytes);
                PublicKey clientLTPub = KeyFactory.getInstance("RSA").generatePublic(ltSpec);
                synchronized (clientPubKeys) {
                    clientPubKeys.put(clientID, clientLTPub);
                    clientPubKeys.notifyAll();
                }
                System.out.println("[KDC][Phase 2] Long-term public key received from " + clientID);

                
                // Wait until all 3 clients have submitted their public keys
                synchronized (clientPubKeys) {
                    while (clientPubKeys.size() < 3) {
                        clientPubKeys.wait();
                    }
                }
                
                // Distribute all OTHER clients' public keys to this client so it can verify their signatures
                for (Map.Entry<String, PublicKey> entry : clientPubKeys.entrySet()) {
                    if (!entry.getKey().equals(clientID)) {
                        byte[] peerPubBytes = entry.getValue().getEncoded();
                        out.writeUTF("PUBKEY");           // type flag
                        out.writeUTF(entry.getKey());     // peer ID
                        out.writeInt(peerPubBytes.length);
                        out.write(peerPubBytes);
                        out.flush();
                        System.out.println("sent public key of " + entry.getKey() + " to " + clientID);
                    }
                }

                // ── CHAT FORWARDING LOOP ──────────────────────────────────────────
                System.out.println("starting chat forwarding for " + clientID);
                while (true) {
                    try {
                         // Protocol: E(Ks, [IDA, M || T_Client])  and  SigA(IDA, M) 
                        String encPayload = in.readUTF();  // E(Ks, [IDA, M || T_Client])
                        String signature  = in.readUTF();  // SigA(IDA, M)

                        System.out.println("Received chat message from " + clientID + " forwarding...");

                        // Forward to all other clients
                        synchronized (clientOuts) {
                            for (Map.Entry<String, DataOutputStream> entry : clientOuts.entrySet()) {
                                if (!entry.getKey().equals(clientID)) {
                                    DataOutputStream dest = entry.getValue();
                                    dest.writeUTF(clientID);   // so receiver knows who sent it
                                    dest.writeUTF(encPayload);
                                    dest.writeUTF(signature);
                                    dest.flush();
                                    System.out.println("[KDC] Forwarded to " + entry.getKey());
                                }
                            }
                        }
                        
                    } catch (IOException e) {
                        System.out.println("[KDC] " + clientID + " disconnected.");
                        break;
                    }
                }

            } catch (Exception e) {
                System.out.println("[KDC] Error in handler for client #" + clientNumber + ": " + e.getMessage());
                e.printStackTrace();
            }
        }
    }

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