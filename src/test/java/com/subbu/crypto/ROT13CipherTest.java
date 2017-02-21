package com.subbu.crypto;

import com.subbu.crypto.impl.CeaserCipher;
import com.subbu.crypto.impl.ROT13Cipher;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotEquals;

/**
 * Created by devsu04 on 20/02/17.
 */

public class ROT13CipherTest {

    private static CryptoService cryptoService = null;
    private String cipherText;
    private String plainText;

    @BeforeClass
    public static void setup() {
        cryptoService = ROT13Cipher.getInstance();
    }

    @Test(testName = "testEncryption", description = "This is a test method to test the ROT13 Cipher encryption", priority = 9)
    public void testEncryption() {
        cipherText = cryptoService.encrypt("ATTACK AT DAWN");
        assertNotEquals(cipherText, "ATTACK AT DAWN");
    }

    @Test(testName = "testDecryption", description = "This is a test method to test the ROT13 Cipher decryption", priority = 10)
    public void testDecryption() {
        cipherText = cryptoService.encrypt("ATTACK AT DAWN");
        plainText = cryptoService.decrypt(cipherText);
        assertEquals(plainText, "ATTACK AT DAWN");
    }
}
