import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.secvault.SecureVault;
import org.wso2.carbon.secvault.SecureVaultUtils;
import org.wso2.carbon.secvault.exception.SecureVaultException;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Created by subhashinie on 10/16/17.
 */
public class FileEncryption {

    private static final Logger log = LoggerFactory.getLogger(FileEncryption.class);
    public static final int AES_Key_Size = 128;

    private Cipher aesCipher;
    SecureVault secureVault;


    public FileEncryption(SecureVault secureVault) throws NoSuchPaddingException, NoSuchAlgorithmException{
        this.secureVault = secureVault;

        // create AES shared key cipher
        aesCipher = Cipher.getInstance("AES");
    }

    public void createAndStoreAESKey() throws SecureVaultException, IOException, NoSuchAlgorithmException {
        //create key
        KeyGenerator kgen = KeyGenerator.getInstance("AES");
        kgen.init(AES_Key_Size);
        byte[] aesKey = kgen.generateKey().getEncoded();
        log.info("Creating and storing AES key");

        //store key = encrypt -> encode -> string
        byte[] encryptedKeyBytes = SecureVaultUtils.base64Encode(secureVault.encrypt(aesKey));
        String encryptedKeyString = new String(SecureVaultUtils.toChars(encryptedKeyBytes));

        File encryptedAesKeyFile = new File(Constants.ENCRYPTED_AES_KEY_FILE);
        FileOutputStream outputStream = new FileOutputStream(encryptedAesKeyFile);
        outputStream.write(SecureVaultUtils.toBytes(encryptedKeyString));
    }

    public void encryptFile(File inFile, File outFile) throws IOException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, SecureVaultException {
        //decrypt AES key using secure vault
        String encryptedAesKeyString = SecureVaultUtils.resolveFileToString(Paths.get(Constants.ENCRYPTED_AES_KEY_FILE));
        byte[] encryptedAesKeyBytes = SecureVaultUtils.base64Decode(SecureVaultUtils.toBytes(encryptedAesKeyString));
        byte[] aesKeyBytes = secureVault.decrypt(encryptedAesKeyBytes);
        log.info("Encrypting file using stored AES key");

        //use AES key to encrypt file
        SecretKeySpec aesKeySpec = new SecretKeySpec(aesKeyBytes, "AES");
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKeySpec);

        FileInputStream inputStream = new FileInputStream(inFile);
        CipherOutputStream cipherOutputStream = new CipherOutputStream(new FileOutputStream(outFile), aesCipher);
        copy(inputStream, cipherOutputStream);
        inputStream.close();
        cipherOutputStream.close();
    }

    public String readFromEncryptedFile(File inFile) throws IOException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, SecureVaultException {
        //decrypt AES key using secure vault
        String encryptedAesKeyString = SecureVaultUtils.resolveFileToString(Paths.get(Constants.ENCRYPTED_AES_KEY_FILE));
        byte[] encryptedAesKeyBytes = SecureVaultUtils.base64Decode(SecureVaultUtils.toBytes(encryptedAesKeyString));
        byte[] aesKeyBytes = secureVault.decrypt(encryptedAesKeyBytes);
        log.info("Decrypting file using stored AES key");


        //use AES key to decrypt file
        SecretKeySpec aesKeySpec = new SecretKeySpec(aesKeyBytes, "AES");
        aesCipher.init(Cipher.DECRYPT_MODE, aesKeySpec);

        CipherInputStream cipherInputStream = new CipherInputStream(new FileInputStream(inFile), aesCipher);
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        copy(cipherInputStream, byteArrayOutputStream);
        byte[] outByteArray = byteArrayOutputStream.toByteArray();
        cipherInputStream.close();
        return new String(SecureVaultUtils.toChars(outByteArray));
    }

    private void copy(InputStream is, OutputStream os) throws IOException {
        int i;
        byte[] b = new byte[1024];
        while((i=is.read(b))!=-1) {
            os.write(b, 0, i);
        }
    }




}
