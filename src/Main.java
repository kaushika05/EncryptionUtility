import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.security.NoSuchAlgorithmException;

public class Main {
    public static void main(String[] args) {
        try {
            // Generate or load a secret key
            SecretKey secretKey = generateOrLoadKey();

            // Encrypt the file
            encryptFile(secretKey);

            // Decrypt the file
            decryptFile(secretKey);

            System.out.println("Encryption and decryption completed successfully.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static SecretKey generateOrLoadKey() throws NoSuchAlgorithmException {
        // load a key from a file or generate one
        File keyFile = new File("secret.key");
        SecretKey secretKey;

        if (keyFile.exists()) {
            // Load the existing key
            try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(keyFile))) {
                secretKey = (SecretKey) ois.readObject();
            } catch (Exception e) {
                e.printStackTrace();
                throw new RuntimeException("Failed to load the secret key.");
            }
        } else {
            // Generate a new key and save it
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);  // adjust the key size as needed
            secretKey = keyGen.generateKey();

            try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(keyFile))) {
                oos.writeObject(secretKey);
            } catch (Exception e) {
                e.printStackTrace();
                throw new RuntimeException("Failed to save the secret key.");
            }
        }

        return secretKey;
    }

    private static void encryptFile(SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        try (FileInputStream inputStream = new FileInputStream("data/input.txt");
             FileOutputStream outputStream = new FileOutputStream("data/output.enc")) {
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                byte[] encryptedBytes = cipher.update(buffer, 0, bytesRead);
                outputStream.write(encryptedBytes);
            }

            byte[] finalBytes = cipher.doFinal();
            outputStream.write(finalBytes);
        }
    }

    private static void decryptFile(SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        try (FileInputStream inputStream = new FileInputStream("data/output.enc");
             FileOutputStream outputStream = new FileOutputStream("data/decrypted.txt")) {
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                byte[] decryptedBytes = cipher.update(buffer, 0, bytesRead);
                outputStream.write(decryptedBytes);
            }

            byte[] finalBytes = cipher.doFinal();
            outputStream.write(finalBytes);
        }
    }
}
