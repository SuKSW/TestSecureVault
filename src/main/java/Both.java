import org.wso2.carbon.secvault.SecureVault;
import org.wso2.carbon.secvault.SecureVaultFactory;
import org.wso2.carbon.secvault.exception.SecureVaultException;

import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Created by subhashinie on 10/16/17.
 */
public class Both {

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException {
        File inputFile = new File(Constants.INPUT_DOC);
        File encryptedFile = new File(Constants.ENCRYPTED_DOC);

        Path secureVaultPath = Paths.get(Constants.CHANGING_FOLDER+"/secure-vault.yaml");
        FileEncryption fileEncryption;

        try {
            SecureVault secureVault = new SecureVaultFactory().getSecureVault(secureVaultPath)
                    .orElseThrow(() -> new SecureVaultException("Error in getting secure vault instance"));

            fileEncryption = new FileEncryption(secureVault);
            fileEncryption.createAndStoreAESKey();
            fileEncryption.encryptFile(inputFile, encryptedFile);
            System.out.println(fileEncryption.readFromEncryptedFile(encryptedFile));

        } catch (IOException e) {
            e.printStackTrace();
        } catch (SecureVaultException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
    }

}
