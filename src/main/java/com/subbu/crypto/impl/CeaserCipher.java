package com.subbu.crypto.impl;

import com.subbu.crypto.CryptoService;
import com.subbu.crypto.utils.CryptoUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Created by devsu04 on 20/02/17.
 *
 * This class uses the Ceaser Cipher(https://learncryptography.com/classical-encryption/caesar-cipher)
 * to encrypt and decrypt a given plain text
 *
 * The Caesar cipher, also known as a shift cipher, is one of the simplest forms of encryption.
 * It is a substitution cipher where each letter in the original message (called the plaintext)
 * is replaced with a letter corresponding to a certain number of letters up or down in the alphabet.
 */
public class CeaserCipher implements CryptoService {

    private static final Logger logger = LoggerFactory.getLogger(CeaserCipher.class);

    /**
     * This shift size to shift the number of characters.
     */
    private int shiftSize;

    /**
     * This variable holds the static instance of the CeaserCipher
     */
    private static CeaserCipher _instance;

    /**
     * The private constructor with a default shiftSize of 7
     */
    private CeaserCipher() {
        this.shiftSize = 7;
    }

    /**
     * The private constructor accepting a shiftSize
     * @param shiftSize
     */
    private CeaserCipher(int shiftSize) {
        this.shiftSize = shiftSize;
    }

    /**
     * Thread safe way of creating a singleton instance of the default CeaserCipher object
     * @return
     */
    public static CryptoService getInstance() {
        if(_instance == null) {
            synchronized (CeaserCipher.class) {
                if(_instance == null) {
                    _instance = new CeaserCipher();
                    logger.info("****** Yeah got an instance of CeaserCipher ******");
                }
            }
        }
        return _instance;
    }

    /**
     * Thread safe way of creating a singleton instance of the CeaserCipher object with shiftSize
     * @param shiftSize
     * @return
     */
    public static CryptoService getInstance(int shiftSize) {
        if(_instance == null) {
            synchronized (CeaserCipher.class) {
                if(_instance == null) {
                    _instance = new CeaserCipher(shiftSize);
                    logger.info("****** Yeah got an instance of CeaserCipher ******");
                }
            }
        }
        return _instance;
    }

    /**
     * This method returns the encrypted text given a plaintext
     *
     * @param plainText
     * @return
     */
    public String encrypt(String plainText) {
        logger.debug("=============================== *** ENCRYPTION *** ===================================================");
        logger.info("Plain text for encryption - {}", plainText);
        char[] _plainText = plainText.toCharArray();
        char[] _cipherText = new char[_plainText.length];
        logger.debug("Shiftsize - {}", shiftSize);
        for(int i=0;i<_plainText.length;i++) {
            _cipherText[i] = CryptoUtils.rollCharacters(_plainText[i],shiftSize);
        }
        logger.info("Cipher text after encryption - {}", String.valueOf(_cipherText));
        return String.valueOf(_cipherText);
    }

    /**
     * This method returns the plaintext given a ciphertext
     *
     * @param cipherText
     * @return
     */
    public String decrypt(String cipherText) {
        logger.debug("=============================== *** DECRYPTION *** ===================================================");
        logger.info("Cipher text for decryption - {}", cipherText);
        char[] _cipherText = cipherText.toCharArray();
        char[] _plainText = new char[_cipherText.length];
        logger.debug("Shiftsize - {}", shiftSize);
        for(int i=0;i<_cipherText.length;i++) {
            _plainText[i] = CryptoUtils.unRollCharacters(_cipherText[i], shiftSize);
        }
        logger.info("Plain text after encryption - {}", String.valueOf(_plainText));
        return String.valueOf(_plainText);
    }
}
