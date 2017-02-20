package com.subbu.crypto;

import com.subbu.crypto.impl.VigenereCipher;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotEquals;

/**
 * Created by devsu04 on 20/02/17.
 */

public class VigenereCipherTest {

    private static CryptoService cryptoService = null;
    private String cipherText;
    private String plainText;

    @BeforeClass
    public static void setup() {
        cryptoService = VigenereCipher.getInstance("gArBlEd");
    }

    @Test(testName = "testEncryption", description = "This is a test method to test the Vigenere Cipher encryption", priority = 3)
    public void testEncryption() {
        cipherText = cryptoService.encrypt("Subbu");
        assertNotEquals(cipherText, "Subbu");
    }

    @Test(testName = "testDecryption", description = "This is a test method to test the Vigenere Cipher decryption", priority = 4)
    public void testDecryption() {
        cipherText = cryptoService.encrypt("Subbu");
        plainText = cryptoService.decrypt(cipherText);
        assertEquals(plainText, "Subbu");
    }
}
