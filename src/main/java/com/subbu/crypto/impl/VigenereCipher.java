package com.subbu.crypto.impl;

import com.subbu.crypto.CryptoService;
import com.subbu.crypto.utils.CryptoUtils;
import org.apache.commons.lang3.CharUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Created by devsu04 on 20/02/17.
 * This class uses the Vigenere Cipher(https://learncryptography.com/classical-encryption/vigenere-cipher)
 * to encrypt and decrypt a given plain text
 *
 * The Vigenère Cipher was developed by mathematician Blaise de Vigenère in the 16th century.
 * The Vigenère Cipher was adapted as a twist on the standard Caesar cipher to reduce the effectiveness of
 * performing frequency analysis on the ciphertext. The cipher accomplishes this using uses a text string
 * (for example, a word) as a key, which is then used for doing a number of alphabet shifts on the plaintext.
 * Similar to the Caesar Cipher, but instead of performing a single alphabet shift across the entire plaintext,
 * the Vigenère cipher uses a key to determine several different shift amounts across the entirety of the message.
 */
public class VigenereCipher implements CryptoService {

    private static final Logger logger = LoggerFactory.getLogger(VigenereCipher.class);

    /**
     * The key to be used for encryption.
     */
    private String key;

    /**
     * This variable holds the static instance of the CeaserCipher
     */
    private static VigenereCipher _instance;

    /**
     * The private constructor with a default shiftSize of 7
     */
    private VigenereCipher() {
        this.key = "aEiOu";
    }

    /**
     * The private constructor accepting a shiftSize
     * @param key
     */
    private VigenereCipher(String key) {
        this.key = key;
    }

    /**
     * Thread safe way of creating a singleton instance of the default CeaserCipher object
     * @return
     */
    public static CryptoService getInstance() {
        if(_instance == null) {
            synchronized (VigenereCipher.class) {
                if(_instance == null) {
                    _instance = new VigenereCipher();
                    logger.info("****** Yeah got an instance of VigenereCipher ******");
                }
            }
        }
        return _instance;
    }

    /**
     * Thread safe way of creating a singleton instance of the CeaserCipher object with shiftSize
     * @param key
     * @return
     */
    public static CryptoService getInstance(String key) {
        if(_instance == null) {
            synchronized (VigenereCipher.class) {
                if(_instance == null) {
                    _instance = new VigenereCipher(key);
                    logger.info("****** Yeah got an instance of VigenereCipher ******");
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
        logger.debug("key - {}", key);
        for(int i=0;i<_plainText.length;i++) {
            _cipherText[i] = getEncryptedChar(_plainText[i], i);
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
        logger.debug("key - {}", key);
        for(int i=0;i<_cipherText.length;i++) {
            _plainText[i] = getDecryptedChar(_cipherText[i], i);
        }
        logger.info("Plain text after encryption - {}", String.valueOf(_plainText));
        return String.valueOf(_plainText);
    }

    /**
     * This is a utility method to encrypt the given character with the corresponding char for encryption
     * from the given key and roll to begining when it reaches the end of the key.
     * @param _char
     * @param pos
     * @return
     */
    private char getEncryptedChar(char _char, int pos) {
        logger.debug("==================================================================================");
        char encChar = '\0';
        if(pos > key.length()) {
            pos = pos - key.length();
        }
        logger.debug("Before rolling the character {} - {}", _char, (int)_char);
        logger.debug("The encryption char selected - {} - {}", key.charAt(pos), CryptoUtils.getAlphaPos(key.charAt(pos)));
        encChar = CryptoUtils.rollCharacters(_char, CryptoUtils.getAlphaPos(key.charAt(pos)));
        logger.debug("After rolling the character {} - {}", (int)encChar, encChar);
        return encChar;
    }

    /**
     * This is a utility method to decrypt the given character with the corresponding char for decryption
     * from the given key and roll to begining when it reaches the end of the key.
     * @param _char
     * @param pos
     * @return
     */
    private char getDecryptedChar(char _char, int pos) {
        logger.debug("==================================================================================");
        char decChar = '\0';
        if(pos > key.length()) {
            pos = pos - key.length();
        }
        logger.debug("Before rolling the character {} - {}", _char, (int)_char);
        logger.debug("The encryption char selected - {} - {}", key.charAt(pos), CryptoUtils.getAlphaPos(key.charAt(pos)));
        decChar = CryptoUtils.unRollCharacters(_char, CryptoUtils.getAlphaPos(key.charAt(pos)));
        logger.debug("After rolling the character {} - {}", (int)decChar, decChar);
        return decChar;
    }
}
