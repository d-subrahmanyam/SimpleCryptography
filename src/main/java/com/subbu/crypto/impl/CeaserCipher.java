package com.subbu.crypto.impl;

import com.subbu.crypto.CryptoService;
import org.apache.commons.lang3.CharUtils;
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
            _cipherText[i] = getEncryptShiftChar(_plainText[i]);
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
            _plainText[i] = getDecryptShiftChar(_cipherText[i]);
        }
        logger.info("Plain text after encryption - {}", String.valueOf(_plainText));
        return String.valueOf(_plainText);
    }

    /**
     * This is a utility method to get the forward encryption of Ceaser Cipher
     * @param _char
     * @return
     */
    private char getEncryptShiftChar(char _char){
        char shiftedChar = '\0';

        // If its not an alphabet either upper or lower return as-is
        if(!CharUtils.isAsciiAlpha(_char)) return _char;

        int iShiftChar = 0;

        logger.debug("==================================================================================");

        if(CharUtils.isAsciiAlphaUpper(_char)) {
            logger.debug("Uppercase");
            logger.debug("Before rolling the character {} - {}", _char, (int)_char);
            iShiftChar = _char + shiftSize;
            if (iShiftChar > 90) {
                int diff = iShiftChar - 90;
                logger.debug("The oversize - {}", diff);
                iShiftChar = 65 + diff -1;
                logger.debug("After rolling the character {} - {}", iShiftChar, (char)iShiftChar);
            }
        } else if(CharUtils.isAsciiAlphaLower(_char)) {
            logger.debug("Lowercase");
            logger.debug("Before rolling the character {} - {}", _char, (int)_char);
            iShiftChar = _char + shiftSize;
            if (iShiftChar > 122) {
                int diff = iShiftChar - 122;
                logger.debug("The oversize - {}", diff);
                iShiftChar = 97 + diff -1;
                logger.debug("After rolling the character {} - {}", iShiftChar, (char)iShiftChar);
            }
        }

        shiftedChar = (char) iShiftChar;
        return shiftedChar;
    }

    /**
     * This is a utility method to get the reverse decryption of Ceaser Cipher
     * @param _char
     * @return
     */
    private char getDecryptShiftChar(char _char){
        char shiftedChar = '\0';

        // If its not an alphabet either upper or lower return as-is
        if(!CharUtils.isAsciiAlpha(_char)) return _char;

        int iShiftChar = 0;

        logger.debug("==================================================================================");

        if(CharUtils.isAsciiAlphaUpper(_char)) {
            logger.debug("Uppercase");
            logger.debug("Before rolling the character {} - {}", _char, (int)_char);
            iShiftChar = _char - shiftSize;
            if (iShiftChar < 65) {
                int diff = _char - 65;
                diff = shiftSize - diff -1;
                logger.debug("The undersize - {}", diff);
                iShiftChar = 90 - diff;
                logger.debug("After rolling the character {} - {}", iShiftChar, (char)iShiftChar);
            }
        } else if(CharUtils.isAsciiAlphaLower(_char)) {
            logger.debug("Lowercase");
            logger.debug("Before rolling the character {} - {}", _char, (int)_char);
            iShiftChar = _char - shiftSize;
            if (iShiftChar < 97) {
                int diff = _char - 97;
                diff = shiftSize - diff -1;
                logger.debug("The undersize - {}", diff);
                iShiftChar = 122 - diff;
                logger.debug("After rolling the character {} - {}", iShiftChar, (char)iShiftChar);
            }
        }

        shiftedChar = (char) iShiftChar;
        return shiftedChar;
    }
}
