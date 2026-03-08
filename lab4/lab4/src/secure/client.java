package secure ;
        
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class client {

    private static final String KDC_HOST         = "localhost";
    private static final int    KDC_PORT          = 1234;

    private static String       myID;
    private static KeyPair      myKeyPair;
    private static SecretKeySpec groupKeyKs;    // AES group key Ks from Phase 2
    private static PublicKey    kdcPublicKey;

    // Peer public keys 
    private static final java.util.Map<String, PublicKey> peerPublicKeys =
            new java.util.concurrent.ConcurrentHashMap<>();

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: java ChatClient \"Client A\"");
            System.exit(1);
        }
        myID = args[0];
        System.out.println(" ----Client [" + myID + " chat---------- \n");

        // Generate RSA key pair for this client
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        myKeyPair = kpg.generateKeyPair();

        Socket socket = new Socket(KDC_HOST, KDC_PORT);
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());
        DataInputStream  in  = new DataInputStream(socket.getInputStream());

        // Authenticated Key Exchange 
        
        // Send our RSA public key
        byte[] myPubKeyBytes = myKeyPair.getPublic().getEncoded();
        out.writeInt(myPubKeyBytes.length);
        out.write(myPubKeyBytes);

        // Receive KDC's RSA public key
        int kdcKeyLen = in.readInt();
        byte[] kdcPubKeyBytes = in.readNBytes(kdcKeyLen);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(kdcPubKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        kdcPublicKey = keyFactory.generatePublic(keySpec);
        System.out.println("[" + myID + "] Received KDC public key.");

        // Send our ID
        out.writeUTF(myID);
        out.flush();

        Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");

        // Receive Message 1: E(PU_Client, [NK1 || IDK])
        String msg1    = in.readUTF();
        cipher.init(Cipher.DECRYPT_MODE, myKeyPair.getPrivate());
        String decMsg1 = new String(cipher.doFinal(Base64.getDecoder().decode(msg1))).replace("\0","").trim();;
        String nonceK  = decMsg1.split("\\|\\|")[0];
        System.out.println("[" + myID + "] Received Message 1. KDC nonce: " + nonceK);

        // Send Message 2: E(PU_KDC, [N_Client || NK])
        String myNonce   = "N" + myID.replace(" ", "") + (int)(Math.random() * 1000);
        String msg2Plain = myNonce + "||" + nonceK;
        cipher.init(Cipher.ENCRYPT_MODE, kdcPublicKey);
        byte[] msg2Encrypt = cipher.doFinal(msg2Plain.getBytes());
        out.writeUTF(Base64.getEncoder().encodeToString(msg2Encrypt));
        out.flush();
        System.out.println("[" + myID + "] Sent Message 2 (our nonce + KDC nonce echo).");

        // Receive Message 3: E(PU_Client, NK) — KDC echoes our nonce back
        String msg3    = in.readUTF();
        cipher.init(Cipher.DECRYPT_MODE, myKeyPair.getPrivate());
        String decMsg3 = new String(cipher.doFinal(Base64.getDecoder().decode(msg3))).replace("\0","").trim();;
        if (!decMsg3.equals(nonceK)) {
            System.err.println("[" + myID + "] ERROR: KDC nonce echo mismatch");
            socket.close();
            return;
        }
        System.out.println("[" + myID + "] KDC verified");

        // Receive Message 4: E(PU_Client, E(PR_KDC, MasterKey))
        String msg4        = in.readUTF();
        cipher.init(Cipher.DECRYPT_MODE, myKeyPair.getPrivate());
        byte[] outerDecrypt = cipher.doFinal(Base64.getDecoder().decode(msg4));
        cipher.init(Cipher.DECRYPT_MODE, kdcPublicKey);
        String masterKey = new String(cipher.doFinal(outerDecrypt),
                java.nio.charset.StandardCharsets.UTF_8).replace("\0", "").trim();
        System.out.println("[" + myID + "] Master key received: " + masterKey);

        // Receive Group Key Ks 
        // Protocol: E(K_Client, [Ks || ID_KDC])
        String encPhase2   = in.readUTF();
        String phase2Plain = simDecrypt(masterKey, encPhase2);
        String[] p2Parts   = phase2Plain.split("\\|\\|");
        byte[] ksBytes     = Base64.getDecoder().decode(p2Parts[0]);
        groupKeyKs         = new SecretKeySpec(ksBytes, "AES");
        System.out.println("[" + myID + "] Group session key Ks received and verified ");

        // Send our long-term public key to KDC so it can distribute to other clients
        // KDC will forward it to peers so they can verify our signatures
        byte[] myLTPubBytes = myKeyPair.getPublic().getEncoded();
        out.writeInt(myLTPubBytes.length);
        out.write(myLTPubBytes);
        out.flush();
        System.out.println("[" + myID + "] public key sent to KDC");

        System.out.println("[" + myID + "] Ready!\n");
        System.out.println("Type a message and press Enter  |  'quit' to exit:\n");

        // ── RECEIVER THREAD ────────────────────────────────────────────────────
        Thread receiver = new Thread(() -> {
            try {
                while (true) {
                    // First message from KDC may be a peer public key registration
                    // or a forwarded chat message — distinguished by a type flag
                    String msgType = in.readUTF();
                    if (msgType.equals("PUBKEY")) {
                        // KDC is distributing a peer's public key
                        String peerID      = in.readUTF();
                        int    pkLen       = in.readInt();
                        byte[] pkBytes     = in.readNBytes(pkLen);
                        X509EncodedKeySpec spec = new X509EncodedKeySpec(pkBytes);
                        PublicKey peerPub  = KeyFactory.getInstance("RSA").generatePublic(spec);
                        peerPublicKeys.put(peerID, peerPub);
                        System.out.println("[" + myID + "] Received public key for " + peerID);
                    } else {
                        // msgType is the senderID (chat message)
                        String senderID   = msgType;
                        String encPayload = in.readUTF();
                        String signature  = in.readUTF();
                        receiveMessage(senderID, encPayload, signature);
                    }
                }
            } catch (IOException e) {
                System.out.println("[" + myID + "] Disconnected from KDC.");
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
        receiver.setDaemon(true);
        receiver.start();

        // ── SENDER LOOP ────────────────────────────────────────────────────────
        Scanner scanner = new Scanner(System.in);
        while (scanner.hasNextLine()) {
            String line = scanner.nextLine().trim();
            if (line.equalsIgnoreCase("quit")) break;
            if (!line.isEmpty()) sendMessage(line, out);
        }
        socket.close();
    }

    // =========================================================================
    // A -> KDC : E(Ks, [IDA, M]),  SigA(IDA, M)
    // =========================================================================
    static void sendMessage(String message, DataOutputStream out) throws Exception {

        // Plaintext inside the encryption: IDA || M
        String plaintext = myID + "||" + message;

        // Step 1 — E(Ks, [IDA, M]): AES-CBC encrypt with group key Ks
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aesCipher.init(Cipher.ENCRYPT_MODE, groupKeyKs, new IvParameterSpec(iv));
        byte[] ciphertext = aesCipher.doFinal(plaintext.getBytes());

        // Prepend IV: [IV (16 bytes) | ciphertext]
        byte[] ivAndCipher = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv,         0, ivAndCipher, 0,         iv.length);
        System.arraycopy(ciphertext, 0, ivAndCipher, iv.length, ciphertext.length);
        String encPayload = Base64.getEncoder().encodeToString(ivAndCipher);

        // Step 2 — SigA(IDA, M): RSA-SHA256 digital signature over IDA || M
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(myKeyPair.getPrivate());
        signer.update(plaintext.getBytes());
        String sigB64 = Base64.getEncoder().encodeToString(signer.sign());

        // Step 3 — Send to KDC: encPayload, signature (no timestamp needed)
        out.writeUTF(encPayload);
        out.writeUTF(sigB64);
        out.flush();

        System.out.println("\n┌─ [" + myID + " SENT] ─────────────────────────────────────────");
        System.out.println("│  Message          : \"" + message + "\"");
        System.out.println("│  Plaintext        : " + plaintext);
        System.out.println("│  E(Ks,[IDA,M])    : " + encPayload.substring(0, Math.min(48, encPayload.length())) + "...");
        System.out.println("│  SigA(IDA,M)      : " + sigB64.substring(0, 32) + "...");
        System.out.println("└──────────────────────────────────────────────────────────");
    }

    //  RECEIVE — AES-CBC decrypt, verify SigA(IDA, M) with sender's public key
    static void receiveMessage(String senderID, String encPayload, String sigB64) {
        try {
            // ── Decrypt E(Ks, [IDA, M]) with group key Ks ────────────────────
            byte[] ivAndCipher = Base64.getDecoder().decode(encPayload);
            byte[] iv          = new byte[16];
            byte[] ciphertext  = new byte[ivAndCipher.length - 16];
            System.arraycopy(ivAndCipher, 0,  iv,         0, 16);
            System.arraycopy(ivAndCipher, 16, ciphertext, 0, ciphertext.length);

            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            aesCipher.init(Cipher.DECRYPT_MODE, groupKeyKs, new IvParameterSpec(iv));
            String plaintext = new String(aesCipher.doFinal(ciphertext));

            // Parse: IDA || M
            String[] parts  = plaintext.split("\\|\\|", 2);
            String msgText  = parts.length == 2 ? parts[1] : plaintext;

            // Verify SigA(IDA, M) with sender's public key 
            PublicKey senderPub = peerPublicKeys.get(senderID);
            String sigStatus;
            if (senderPub != null) {
                Signature verifier = Signature.getInstance("SHA256withRSA");
                verifier.initVerify(senderPub);
                verifier.update(plaintext.getBytes());
                boolean valid = verifier.verify(Base64.getDecoder().decode(sigB64));
                sigStatus = valid ? "VALID" : "INVALID — message may be tampered!";
            } else {
                sigStatus = "UNVERIFIED (peer public key not yet received)";
            }

            System.out.println("\n┌─ [" + myID + " RECEIVED from " + senderID + "] ─────────────────────");
            System.out.println("│  Message        : \"" + msgText + "\"");
            System.out.println("│  Decrypted with : Ks (AES-CBC)");
            System.out.println("│  Plaintext      : " + plaintext);
            System.out.println("│  SigA(IDA,M)    : " + sigStatus);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    
    
    static String simDecrypt(String key, String ciphertext) {
        String prefix = "ENC[" + key + "]:";
        if (ciphertext.startsWith(prefix)) {
            return ciphertext.substring(prefix.length());
        }
        throw new IllegalArgumentException("Decryption failed: wrong key.");
    }
}
