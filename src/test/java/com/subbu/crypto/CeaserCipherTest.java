package com.subbu.crypto;

import com.subbu.crypto.impl.CeaserCipher;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import static org.testng.Assert.*;

/**
 * Created by devsu04 on 20/02/17.
 */

public class CeaserCipherTest {

    private static CryptoService cryptoService = null;
    private String cipherText;
    private String plainText;

    @BeforeClass
    public static void setup() {
        cryptoService = CeaserCipher.getInstance(9);
    }

    @Test(testName = "testEncryption", description = "This is a test method to test the Ceaser Cipher encryption", priority = 1)
    public void testEncryption() {
        cipherText = cryptoService.encrypt("Subbu");
        assertNotEquals(cipherText, "Subbu");
    }

    @Test(testName = "testDecryption", description = "This is a test method to test the Ceaser Cipher decryption", priority = 2)
    public void testDecryption() {
        cipherText = cryptoService.encrypt("Subbu");
        plainText = cryptoService.decrypt(cipherText);
        assertEquals(plainText, "Subbu");
    }
}
