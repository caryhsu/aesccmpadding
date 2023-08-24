import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Security;
import java.util.Arrays;

public class AESCCMExampleWithBC {

    public static byte[] ccmEncrypt(byte[] plaintext, byte[] aad, byte[] key, byte[] nonce) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        Cipher cipher = Cipher.getInstance("AES/CCM/PKCS7Padding", "BC");
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        GCMParameterSpec parameterSpec = new GCMParameterSpec(17 * 8, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, parameterSpec);
        cipher.updateAAD(aad);

        return cipher.doFinal(plaintext);
    }
    
    public static byte[] ccmDecrypt(byte[] ciphertext, byte[] aad, byte[] key, byte[] nonce) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        Cipher cipher = Cipher.getInstance("AES/CCM/PKCS7Padding", "BC");
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        GCMParameterSpec parameterSpec = new GCMParameterSpec(17 * 8, nonce);

        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, parameterSpec);
        cipher.updateAAD(aad);

        return cipher.doFinal(ciphertext);
    }

    public static void main(String[] args) throws Exception {
        byte[] key = "0123456789abcdef".getBytes();
        byte[] nonce = "0123456789abc".getBytes();
        byte[] plaintext = "0123456789abcdef".getBytes();
        byte[] aad = "0123456789abcdef".getBytes();

        byte[] encrypted = ccmEncrypt(plaintext, aad, key, nonce);
        byte[] decrypted = ccmDecrypt(encrypted, aad, key, nonce);

        System.out.println("Plain Text (String): " + new String(plaintext));
        System.out.println("Plain Text (HEX)   : " + toHexString(plaintext));
        System.out.println("plain len          : " + plaintext.length);
        System.out.println("AAD                : " + new String(aad));
        System.out.println("AAD length         : " + aad.length);
        System.out.println("Key                : " + new String(key));
        System.out.println("nonce              : " + new String(nonce));
        System.out.println("crypt(HEX)         : " + toHexString(encrypted));
        System.out.println("decrypt(HEX)       : " + toHexString(decrypted));
        System.out.println("decrypt(String)    : " + new String(decrypted));
        System.out.println("result             : " + decrypted.length);
    }
    
    public static String toHexString(byte[] byteArray) {
        StringBuilder result = new StringBuilder();
        for (byte b : byteArray) {
            result.append(String.format("%02x ", b));
        }
        return result.toString().trim(); // 去除末尾的空白
    }

}


