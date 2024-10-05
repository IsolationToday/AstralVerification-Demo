package me.astral.verify.demo.utils;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class StringUtil {

    public static byte[] ENCRYPT(byte[] string, String rsaKey, String aesKey){
        return RSAENCRYPT(aesEncrypt(string, aesKey), rsaKey);
    }

    public static byte[] DECRYPT(byte[] string, String rsaKey, String aesKey){
        return aesDecrypt(RSADECRYPT(string,rsaKey), aesKey);
    }

    public static byte[] RSAENCRYPT(byte[] string, String rsaKey){
        if (string == null) return null;
        try {
            X509EncodedKeySpec spec = new X509EncodedKeySpec(Base64.getDecoder().decode(rsaKey));
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PublicKey publicKey = kf.generatePublic(spec);

            Cipher encryptCipher = Cipher.getInstance("RSA");
            encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
            int inputLength = string.length;
            List<byte[]> encryptedData = new ArrayList<>();
            int offset = 0;

            while (offset < inputLength) {
                int length = Math.min(inputLength - offset, 2048 / 8 - 11);
                byte[] encryptedBlock = encryptCipher.doFinal(string, offset, length);
                encryptedData.add(encryptedBlock);
                offset += length;
            }
            int totalLength = encryptedData.stream().mapToInt(b -> b.length).sum();
            byte[] result = new byte[totalLength];
            int currentPosition = 0;
            for (byte[] block : encryptedData) {
                System.arraycopy(block, 0, result, currentPosition, block.length);
                currentPosition += block.length;
            }
            return result;
        } catch (IllegalBlockSizeException | BadPaddingException | NoSuchPaddingException | NoSuchAlgorithmException |
                 InvalidKeySpecException | InvalidKeyException ignored) {

        }
        return null;
    }

    public static byte[] RSADECRYPT(byte[] string, String rsaKey){
        if (string == null) return null;
        try {
            X509EncodedKeySpec spec = new X509EncodedKeySpec(Base64.getDecoder().decode(rsaKey));
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PublicKey publicKey = kf.generatePublic(spec);

            Cipher decryptCipher = Cipher.getInstance("RSA");
            decryptCipher.init(Cipher.DECRYPT_MODE, publicKey);
            int inputLength = string.length;
            List<byte[]> encryptedData = new ArrayList<>();
            int offset = 0;

            while (offset < inputLength) {
                int length = Math.min(inputLength - offset,  2048 / 8);
                byte[] encryptedBlock = decryptCipher.doFinal(string, offset, length);
                encryptedData.add(encryptedBlock);
                offset += length;
            }
            int totalLength = encryptedData.stream().mapToInt(b -> b.length).sum();
            byte[] result = new byte[totalLength];
            int currentPosition = 0;
            for (byte[] block : encryptedData) {
                System.arraycopy(block, 0, result, currentPosition, block.length);
                currentPosition += block.length;
            }
            return result;
        } catch (NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException |
                 InvalidKeySpecException | BadPaddingException | InvalidKeyException ignored) {
        }
        return null;
    }

    public static byte[] aesEncrypt(byte[] bytes, String aesKey) {
        if (bytes == null) return null;
        try {
            int aesKeyLength = 32;
            byte[] aesKeyBytes = new byte[aesKeyLength];
            System.arraycopy(aesKey.getBytes(), 0, aesKeyBytes, 0, aesKeyLength);
            SecretKeySpec spec = new SecretKeySpec(aesKeyBytes,"AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE,spec);
            return cipher.doFinal(bytes);
        } catch (NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException | BadPaddingException |
                 InvalidKeyException ignored) {
        }
        return null;
    }

    public static byte[] aesDecrypt(byte[] bytes, String aesKey) {
        if (bytes == null) return null;
        try {
            int aesKeyLength = 32;
            byte[] aesKeyBytes = new byte[aesKeyLength];
            System.arraycopy(aesKey.getBytes(), 0, aesKeyBytes, 0, aesKeyLength);
            SecretKeySpec spec = new SecretKeySpec(aesKeyBytes,"AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE,spec);
            return cipher.doFinal(bytes);
        } catch (NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException | BadPaddingException |
                 InvalidKeyException ignored) {
        }
        return null;
    }
}
