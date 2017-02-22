package com.subbu.crypto.impl;

import com.subbu.crypto.CryptoService;
import com.subbu.crypto.utils.CryptoUtils;
import org.apache.commons.lang3.CharUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.math3.util.ArithmeticUtils;
import org.apache.commons.math3.util.MathUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Created by devsu04 on 20/02/17.
 *
 * This class uses the Affine Cipher(http://practicalcryptography.com/ciphers/classical-era/affine/)
 * to encrypt and decrypt a given plain text
 *
 * The 'key' for the Affine cipher consists of 2 numbers, we'll call them a and b. The following discussion
 * assumes the use of a 26 character alphabet (m = 26). a should be chosen to be relatively prime to m
 * (i.e. a should have no factors in common with m). For example 15 and 26 have no factors in common, so 15
 * is an acceptable value for a, however 12 and 26 have factors in common (e.g. 2) so 12 cannot be used for
 * a value of a. When encrypting, we first convert all the letters to numbers ('a'=0, 'b'=1, ..., 'z'=25).
 * The ciphertext letter c, for any given letter p is (remember p is the number representing a letter):
 *
 * c = a*p +b (mod m), 1 <= a <=m, 1 <= b <= m
 *
 * The decryption function is
 *
 * p = (a pow -1)(c - b)(mod m)
 */
public class AffineCipher implements CryptoService{

    private static final Logger logger = LoggerFactory.getLogger(AffineCipher.class);

    /**
     * The key-A used for encryption.
     */
    private int keyA;

    /**
     * The key-B used for encryption.
     */
    private int keyB;

    /**
     * The inverse value of keyA
     */
    private int inverseOfKeyA;

    /**
     * This variable holds the static instance of the AffineCipher
     */
    private static AffineCipher _instance;

    /**
     * The private constructor
     */
    private AffineCipher() {
        int _keyA = generateKey();
        int _keyB = generateKey();
        while(_keyA == _keyB) {
            _keyB = generateKey();
        }
        this.keyA = _keyA; // 5;
        logger.debug("The keyA - {}", keyA);
        inverseOfKeyA = calculateInverseOfInt(keyA); // 21;
        logger.debug("Inverse of keyA - {}", inverseOfKeyA);
        this.keyB = _keyB; // 9;
        logger.debug("The keyB - {}", keyB);
    }

    /**
     * Thread safe way of creating a singleton instance of the default AffineCipher object
     * @return
     */
    public static CryptoService getInstance() {
        if(_instance == null) {
            synchronized (AffineCipher.class) {
                if(_instance == null) {
                    _instance = new AffineCipher();
                    logger.info("****** Yeah got an instance of AffineCipher ******");
                }
            }
        }
        return _instance;
    }

    /**
     * This method returns the key-A generated during the process of encryption
     * @return
     */
    public int getKeyA() {
        return this.keyA;
    }

    /**
     * This method returns the key-B generated during the process of encryption
     * @return
     */
    public int getKeyB() {
        return this.keyB;
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
        for(int i=0;i<_plainText.length;i++) {
            if(CharUtils.isAsciiAlpha(_plainText[i])) {
                _cipherText[i] = getEncryptedChar(_plainText[i]);
            } else {
                _cipherText[i] = _plainText[i];
            }
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
        for(int i=0;i<_cipherText.length;i++) {
            if(CharUtils.isAsciiAlpha(_cipherText[i])) {
                _plainText[i] = getDecryptedChar(_cipherText[i]);
                logger.debug("Got the decrypted char - {}", _plainText[i]);
            } else {
                _plainText[i] = _cipherText[i];
            }
        }
        logger.info("Plain text after decryption - {}", String.valueOf(_plainText));
        return String.valueOf(_plainText);
    }

    /**
     * This is a utility function that calculates the encrypted char based on the AffineCipher Algorithm
     *
     * @param _char
     * @return
     */
    private char getEncryptedChar(char _char) {
        logger.debug("================ iteration - {}", _char);
        char encChar = '\0';
        CryptoUtils.CASE _case = CryptoUtils.CASE.LOWERCASE;
        if(CharUtils.isAsciiAlpha(_char)) {
            if(CharUtils.isAsciiAlphaLower(_char)) _case  = CryptoUtils.CASE.LOWERCASE;
            else if(CharUtils.isAsciiAlphaUpper(_char)) _case  = CryptoUtils.CASE.UPPERCASE;
        }
        int pos = CryptoUtils.getAlphaPos(_char);
        int newCharPos = (keyA * pos + keyB) % 26;
        logger.debug("Applying the algorithm - newCharPos = ({} * {} + {}) % 26 - {}", keyA, pos, keyB, newCharPos);
        encChar = CryptoUtils.getAlphaAtPos(newCharPos, _case);
        logger.debug("Encrypted char - {}", encChar);
        return encChar;
    }

    /**
     * This is a utility function that calculates the decrypted char based on the AffineCipher Algorithm
     *
     * @param _char
     * @return
     */
    private char getDecryptedChar(char _char) {
        logger.debug("================ iteration - {}", _char);
        char decChar = '\0';
        CryptoUtils.CASE _case = CryptoUtils.CASE.LOWERCASE;
        if(CharUtils.isAsciiAlpha(_char)) {
            if(CharUtils.isAsciiAlphaLower(_char)) _case  = CryptoUtils.CASE.LOWERCASE;
            else if(CharUtils.isAsciiAlphaUpper(_char)) _case  = CryptoUtils.CASE.UPPERCASE;
        }
        int pos = CryptoUtils.getAlphaPos(_char);
        int actualCharPos = (inverseOfKeyA * (pos - keyB));
        actualCharPos = actualCharPos%26;
        if(actualCharPos < 0) actualCharPos = 26 + actualCharPos; // This was necessary as Java does not calculate the modulo of a -ve integer properly
        logger.debug("Applying the algorithm - actualCharPos = {} * ({} - {}) = {} = () % 26 = {}", inverseOfKeyA, pos, keyB, inverseOfKeyA * (pos - keyB), actualCharPos);
        decChar = CryptoUtils.getAlphaAtPos(actualCharPos, _case);
        return decChar;
    }

    /**
     * This is a utility method to generate key based on the following criteria
     * - Choose a number relatively prime to 26, assuming we are using a 26 alphabet lang
     * - The chosen number and 26 should not be sharing any factors.
     *
     * @return
     */
    private int generateKey(){
        int _key = 0;
        int rVal = CryptoUtils.generateRandom(2, 26);
        logger.debug("The random number generated - {}", rVal);
        int gcd = ArithmeticUtils.gcd(rVal, 26);
        logger.debug("The gcd of {} and {} was - {}", rVal, 26, gcd);
        while(gcd > 1) {
            logger.debug("Hmmm... Seems like we have a GCD. Let's generate a fresh Random number and calculate the GCD again.");
            rVal = CryptoUtils.generateRandom(2, 26);
            logger.debug("The random number generated - {}", rVal);
            gcd = ArithmeticUtils.gcd(rVal, 26);
            logger.debug("The gcd of {} and {} was - {}", rVal, 26, gcd);
        }
        _key = rVal;
        return _key;
    }

    /**
     * This is a utility function that calculates the invserse of the given number
     *
     * @param number
     * @return
     */
    private int calculateInverseOfInt(int number){
        int aInv = 0;
        for(int i=1; i<26; i+=2) {
            int tmp = (number * i) % 26;
            if(tmp == 1) {
                aInv = i;
                break;
            }
        }
        return aInv;
    }

}
