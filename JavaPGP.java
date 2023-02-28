import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * An implementation of PGP encryption (PGP = Pretty Good Privacy)
 */
public final class JavaPGP {

    /**
     * The message is created like so:
     * - Generates a random KeyPair
     * - Encrypt the message with the private key from the generated key pair
     * - Encrypt the generated public key with given public key
     *
     * @param message The message to encrypt
     * @param key     The key to encrypt with
     * @return The encrypted message
     * @throws GeneralSecurityException
     */
    public static byte[] encrypt(byte[] message, PublicKey publickey) throws GeneralSecurityException {
        // generate symetric encryption key (AES)
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256); // The AES key size in number of bits
        SecretKey secrectKey = generator.generateKey();

        // encrypt message using symetric encryption key ( AES encrypt plaintext )
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.ENCRYPT_MODE, secrectKey);
        byte[] encryptedMessage = aesCipher.doFinal(message);

        // encrypt the symetric encryption key using the public asemtric encryption key
        // (RSA encrypt AES)
        Cipher rsacipher = Cipher.getInstance("RSA");
        rsacipher.init(Cipher.PUBLIC_KEY, publickey);
        byte[] encryptedSecrectKey = rsacipher.doFinal(secrectKey.getEncoded());

        // Create Byte Buffer to format output data
        //allocate 4 extra bytes for the length of the AES key int
        ByteBuffer buffer = ByteBuffer.allocate((encryptedSecrectKey.length + encryptedMessage.length) + 4);
        buffer.putInt(encryptedSecrectKey.length);
        buffer.put(encryptedSecrectKey);
        buffer.put(encryptedMessage);
        return buffer.array();
    }

    /**
     * The message is decrypted like so:
     * - Read the encrypted public key
     * - Decrypt the public key with the private key
     * - Read the encrypted message
     * - Use the decrypted public key to decrypt the encrypted message
     * 
     * @param message The encrypted message
     * @param key     The private key
     * @return The decrypted message
     * @throws GeneralSecurityException
     */
    public static byte[] decrypt(byte[] message, PrivateKey privatekey) throws GeneralSecurityException {
        // Read first 4 bytes into integer size of encrypted AES key
        ByteBuffer buffer = ByteBuffer.wrap(message);
        int aeskeylength = buffer.getInt();

        // Read the next x bytes to get the encrypted array
        // ( x being the first 4 bytes of the array as an integer, see above )
        byte[] encyptedSecrectKey = new byte[aeskeylength];
        buffer.get(encyptedSecrectKey);

        // Decrypt the AES key using the RSA private key
        Cipher rsacipher = Cipher.getInstance("RSA");
        rsacipher.init(Cipher.DECRYPT_MODE, privatekey);
        byte[] encodedSecrectKey = rsacipher.doFinal(encyptedSecrectKey);
        SecretKey SecrectKey = getSecretKey(encodedSecrectKey);

        //Using the decrypted AES key decrypt the remaining Byte array into the message
        Cipher aescipher = Cipher.getInstance("AES");
        aescipher.init(Cipher.DECRYPT_MODE, SecrectKey);
        byte[] encryptedMessage = new byte[buffer.remaining()];
        buffer.get(encryptedMessage);

        return aescipher.doFinal(encryptedMessage);
    }
    //generate Public key from byte array
    public static PublicKey getPublicKey(byte[] encodedKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory factory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec encodedKeySpec = new X509EncodedKeySpec(encodedKey);
        return factory.generatePublic(encodedKeySpec);
    }
    //generate Private key from byte array
    public static PrivateKey getPrivateKey(byte[] encodedKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory factory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec encodedKeySpec = new PKCS8EncodedKeySpec(encodedKey);
        return factory.generatePrivate(encodedKeySpec);
    }
    //generate Secrect key from byte array
    public static SecretKey getSecretKey(byte[] encodedKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        return new SecretKeySpec(encodedKey, 0, encodedKey.length, "AES");
    }

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(4096, SecureRandom.getInstance("SHA1PRNG"));
        return keyPairGenerator.generateKeyPair();
    }
}
