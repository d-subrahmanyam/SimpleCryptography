package com.subbu.crypto.impl;

import com.subbu.crypto.CryptoService;
import com.subbu.crypto.utils.CryptoUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Created by devsu04 on 20/02/17.
 */
public class OneTimePadCipher implements CryptoService{

    private static final Logger logger = LoggerFactory.getLogger(OneTimePadCipher.class);

    /**
     * The key used for encryption.
     */
    private String key;

    /**
     * This variable holds the static instance of the OneTimePadCipher
     */
    private static OneTimePadCipher _instance;

    /**
     * The private constructor
     */
    private OneTimePadCipher() {
    }

    /**
     * Thread safe way of creating a singleton instance of the default OneTimePadCipher object
     * @return
     */
    public static CryptoService getInstance() {
        if(_instance == null) {
            synchronized (OneTimePadCipher.class) {
                if(_instance == null) {
                    _instance = new OneTimePadCipher();
                    logger.info("****** Yeah got an instance of OneTimePadCipher ******");
                }
            }
        }
        return _instance;
    }

    /**
     * This method returns the key generated during the process of encryption
     * @return
     */
    public String getKey() {
        return this.key;
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
        StringBuffer _key = new StringBuffer();
        for(int i=0;i<_plainText.length;i++) {
            int shiftSize = CryptoUtils.generateRandom();
            logger.debug("Shiftsize - {}", shiftSize);
            _cipherText[i] = CryptoUtils.rollCharacters(_plainText[i],shiftSize);
            _key.append(String.valueOf(shiftSize)).append(CryptoUtils.COMMA);
        }
        key = StringUtils.left(_key.toString(),_key.toString().length()-1);
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
     * This is a utility method to decrypt the given character with the corresponding char for decryption
     * from the given key and roll to begining when it reaches the end of the key.
     * @param _char
     * @param pos
     * @return
     */
    private char getDecryptedChar(char _char, int pos) {
        logger.debug("==================================================================================");
        char decChar = '\0';
        String[] _keys = StringUtils.split(key, CryptoUtils.COMMA);
        if(pos > _keys.length) {
            pos = pos - _keys.length;
        }
        logger.debug("Before rolling the character {} - {}", _char, (int)_char);
        decChar = CryptoUtils.unRollCharacters(_char, Integer.parseInt(_keys[pos]));
        logger.debug("After rolling the character {} - {}", (int)decChar, decChar);
        return decChar;
    }
}
