package com.subbu.crypto;

import com.subbu.crypto.impl.OneTimePadCipher;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotEquals;

/**
 * Created by devsu04 on 20/02/17.
 */
public class OneTimePadCipherTest {

    private static CryptoService cryptoService = null;
    private String cipherText;
    private String plainText;

    @BeforeClass
    public static void setup() {
        cryptoService = OneTimePadCipher.getInstance();
    }

    @Test(testName = "testEncryption", description = "This is a test method to test the OneTimePad Cipher encryption", priority = 5)
    public void testEncryption() {
        cipherText = cryptoService.encrypt("Subbu");
        assertNotEquals(cipherText, "Subbu");
    }

    @Test(testName = "testDecryption", description = "This is a test method to test the OneTimePad Cipher decryption", priority = 6)
    public void testDecryption() {
        cipherText = cryptoService.encrypt("Subbu");
        plainText = cryptoService.decrypt(cipherText);
        assertEquals(plainText, "Subbu");
    }
}
