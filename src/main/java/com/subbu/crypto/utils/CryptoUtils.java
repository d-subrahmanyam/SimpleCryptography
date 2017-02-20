package com.subbu.crypto.utils;

import org.apache.commons.lang3.CharUtils;
import org.apache.commons.lang3.RandomUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This is a utility class used in the various crypto algorithms.
 * Created by devsu04 on 20/02/17.
 */
public class CryptoUtils {

    private static final Logger logger = LoggerFactory.getLogger(CryptoUtils.class);

    public static final String COMMA = ",";

    /**
     * This is a utility method to roll the characters
     * @param _char
     * @return
     */
    public static char rollCharacters(char _char, int shiftSize) {
        char shiftedChar = '\0';

        // If its not an alphabet either upper or lower return as-is
        if(!CharUtils.isAsciiAlpha(_char)) return _char;

        int iShiftChar = 0;

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
     * This is a utility method to unRoll the characters
     * @param _char
     * @param shiftSize
     * @return
     */
    public static char unRollCharacters(char _char, int shiftSize) {
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

    /**
     * This is a utility method to get the alphabet positon of a given character
     * @param _alpha
     * @return
     */
    public static int getAlphaPos(char _alpha) {
        int pos = 0;
        logger.debug("the alpha position being asked for - {} - {}", _alpha, (int)_alpha);
        if(CharUtils.isAsciiAlphaUpper(_alpha)) {
            logger.debug("Uppercase");
            pos = _alpha - 65;
        } else if (CharUtils.isAsciiAlphaLower(_alpha)) {
            logger.debug("Lowercase");
            pos = _alpha - 97;
        }
        logger.debug("the alpha position for - {} - {}", _alpha, pos);
        return pos;
    }

    /**
     * This is a utility method to get a random value between 1-26
     * @return
     */
    public static int generateRandom() {
        int rVal = 0;
        rVal = RandomUtils.nextInt(1,24);
        logger.debug("Random number generated - {}", rVal);
        return rVal;
    }
}
