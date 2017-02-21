package com.subbu.crypto;

import com.subbu.crypto.impl.AffineCipher;
import com.subbu.crypto.impl.ROT13Cipher;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotEquals;

/**
 * Created by devsu04 on 20/02/17.
 */

public class AffineCipherTest {

    private static CryptoService cryptoService = null;
    private String cipherText;
    private String plainText;

    @BeforeClass
    public static void setup() {
        cryptoService = AffineCipher.getInstance();
    }

    @Test(testName = "testEncryption", description = "This is a test method to test the Affine Cipher encryption", priority = 11)
    public void testEncryption() {
        cipherText = cryptoService.encrypt("Defend the east wall of the castle");
        assertNotEquals(cipherText, "Defend the east wall of the castle");
    }

    @Test(testName = "testDecryption", description = "This is a test method to test the Affine Cipher decryption", priority = 12)
    public void testDecryption() {
        cipherText = cryptoService.encrypt("Defend the east wall of the castle");
        plainText = cryptoService.decrypt(cipherText);
        assertEquals(plainText, "Defend the east wall of the castle");
    }
}
