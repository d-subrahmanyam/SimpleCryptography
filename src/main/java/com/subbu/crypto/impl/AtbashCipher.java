package com.subbu.crypto.impl;

import com.subbu.crypto.CryptoService;
import com.subbu.crypto.utils.CryptoUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Created by devsu04 on 21/02/17.
 *
 * This class uses the Atbash Cipher(http://practicalcryptography.com/ciphers/classical-era/atbash-cipher/)
 * to encrypt and decrypt a given plain text
 *
 * The Atbash cipher is a substitution cipher with a specific key where the letters of the alphabet are reversed.
 * I.e. all 'A's are replaced with 'Z's, all 'B's are replaced with 'Y's, and so on. It was originally used for
 * the Hebrew alphabet, but can be used for any alphabet.
 * The Atbash cipher offers almost no security, and can be broken very easily. Even if an adversary doesn't know
 * a piece of ciphertext has been enciphered with the Atbash cipher, they can still break it by assuming it is a
 * substitution cipher and determining the key using hill-climbing. The Atbash cipher is also an Affine cipher
 * with a=25 and b = 25, so breaking it as an affine cipher also works.
 */
public class AtbashCipher implements CryptoService {

    private static final Logger logger = LoggerFactory.getLogger(AtbashCipher.class);

    /**
     * This variable holds the static instance of the OneTimePadCipher
     */
    private static AtbashCipher _instance;

    /**
     * The private constructor
     */
    private AtbashCipher() {
    }

    /**
     * Thread safe way of creating a singleton instance of the default AtbashCipher object
     * @return
     */
    public static CryptoService getInstance() {
        if(_instance == null) {
            synchronized (AtbashCipher.class) {
                if(_instance == null) {
                    _instance = new AtbashCipher();
                    logger.info("****** Yeah got an instance of AtbashCipher ******");
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
        logger.debug("Shiftsize - {}", CryptoUtils.DEFAULT_SHIFY_SIZE);
        for(int i=0;i<_plainText.length;i++) {
            _cipherText[i] = CryptoUtils.rollCharacters(_plainText[i],CryptoUtils.DEFAULT_SHIFY_SIZE);
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
        logger.debug("Shiftsize - {}", CryptoUtils.DEFAULT_SHIFY_SIZE);
        for(int i=0;i<_cipherText.length;i++) {
            _plainText[i] = CryptoUtils.unRollCharacters(_cipherText[i], CryptoUtils.DEFAULT_SHIFY_SIZE);
        }
        logger.info("Plain text after encryption - {}", String.valueOf(_plainText));
        return String.valueOf(_plainText);
    }
}
