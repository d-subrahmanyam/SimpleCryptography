package com.subbu.crypto.impl;

import com.subbu.crypto.CryptoService;
import com.subbu.crypto.utils.CryptoUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Created by devsu04 on 20/02/17.
 *
 * This class uses the ROT13 Cipher(http://practicalcryptography.com/ciphers/classical-era/rot13/)
 * to encrypt and decrypt a given plain text
 *
 * The ROT13 cipher is a substitution cipher with a specific key where the letters of the alphabet are
 * offset 13 places. I.e. all 'A's are replaced with 'N's, all 'B's are replaced with 'O's, and so on.
 * It can also be thought of as a Caesar cipher with a shift of 13.
 * The ROT13 cipher offers almost no security, and can be broken very easily. Even if an adversary doesn't
 * know a piece of ciphertext has been enciphered with the ROT13 cipher, they can still break it by assuming
 * it is a substitution cipher and determining the key using hill-climbing. The ROT13 cipher is also an
 * Caesar cipher with a key of 13, so breaking it as a Caesar cipher also works.
 */
public class ROT13Cipher implements CryptoService {

    private static final Logger logger = LoggerFactory.getLogger(ROT13Cipher.class);

    /**
     * This shift size to shift the number of characters.
     */
    private int shiftSize;

    /**
     * This variable holds the static instance of the ROT13Cipher
     */
    private static ROT13Cipher _instance;

    /**
     * The private constructor with a default shiftSize of 7
     */
    private ROT13Cipher() {
        this.shiftSize = 13;
    }

    /**
     * Thread safe way of creating a singleton instance of the default ROT13Cipher object
     * @return
     */
    public static CryptoService getInstance() {
        if(_instance == null) {
            synchronized (ROT13Cipher.class) {
                if(_instance == null) {
                    _instance = new ROT13Cipher();
                    logger.info("****** Yeah got an instance of ROT13Cipher ******");
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
