package com.subbu.crypto;

/**
 * Created by devsu04 on 20/02/17.
 */
public interface CryptoService {

    /**
     * This method returns the encrypted text given a plaintext
     * @param plainText
     * @return
     */
    public String encrypt(String plainText);

    /**
     * This method returns the plaintext given a ciphertext
     * @param cipherText
     * @return
     */
    public String decrypt(String cipherText);
}
