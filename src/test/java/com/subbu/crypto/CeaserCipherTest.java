package com.subbu.crypto;

import com.subbu.crypto.impl.CeaserCipher;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import static org.junit.Assert.*;

/**
 * Created by devsu04 on 20/02/17.
 */

@FixMethodOrder(value = MethodSorters.NAME_ASCENDING)
public class CeaserCipherTest {

    private static CryptoService cryptoService = null;
    private String cipherText;
    private String plainText;

    @BeforeClass
    public static void setup() {
        cryptoService = CeaserCipher.getInstance(9);
    }

    @Test
    public void firstTestEncryption() {
        cipherText = cryptoService.encrypt("Subbu");
        assertNotEquals(cipherText, "Subbu");
    }

    @Test
    public void nextTestDecryption() {
        cipherText = cryptoService.encrypt("Subbu");
        plainText = cryptoService.decrypt(cipherText);
        assertEquals(plainText, "Subbu");
    }
}
