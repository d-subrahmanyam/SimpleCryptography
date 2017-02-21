package com.subbu.crypto;

import com.subbu.crypto.impl.AtbashCipher;
import com.subbu.crypto.impl.CeaserCipher;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotEquals;

/**
 * Created by devsu04 on 20/02/17.
 */

public class AtbashCipherTest {

    private static CryptoService cryptoService = null;
    private String cipherText;
    private String plainText;

    @BeforeClass
    public static void setup() {
        cryptoService = AtbashCipher.getInstance();
    }

    @Test(testName = "testEncryption", description = "This is a test method to test the Atbash Cipher encryption", priority = 7)
    public void testEncryption() {
        cipherText = cryptoService.encrypt("defend the east wall of the castle");
        assertNotEquals(cipherText, "defend the east wall of the castle");
    }

    @Test(testName = "testDecryption", description = "This is a test method to test the Atbash Cipher decryption", priority = 8)
    public void testDecryption() {
        cipherText = cryptoService.encrypt("defend the east wall of the castle");
        plainText = cryptoService.decrypt(cipherText);
        assertEquals(plainText, "defend the east wall of the castle");
    }
}
