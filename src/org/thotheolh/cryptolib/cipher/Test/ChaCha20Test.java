/*
 * RFC 7539 Encryption Test for ChaCha20.
 */
package org.thotheolh.cryptolib.cipher.Test;

import org.thotheolh.cryptolib.cipher.ChaCha20;
import org.thotheolh.cryptolib.util.BinUtils;
import org.thotheolh.cryptolib.math.MathUtil;

/**
 *
 * @author Thotheolh
 */
public class ChaCha20Test {

    public static void matrixAdd() {
        byte[] a = new byte[]{(byte) 0x4A, (byte) 0x00, (byte) 0x00, (byte) 0x00};
        byte[] b = new byte[]{(byte) 0x9E, (byte) 0x83, (byte) 0xD0, (byte) 0xCB};
        byte[] r = new byte[]{(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00};
        MathUtil.mod32Add(a, (short) 0, b, (short) 0, r, (short) 0);
        System.out.println("Result for r: " + BinUtils.toHexString(r));
    }

    public static void quarterRoundTest() {
        // input
        byte[] a = new byte[]{(byte) 0x11, (byte) 0x11, (byte) 0x11, (byte) 0x11};
        byte[] b = new byte[]{(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04};
        byte[] c = new byte[]{(byte) 0x9b, (byte) 0x8d, (byte) 0x6F, (byte) 0x43};
        byte[] d = new byte[]{(byte) 0x01, (byte) 0x23, (byte) 0x45, (byte) 0x67};

        // KAT
        byte[] a1 = new byte[]{(byte) 0xEA, (byte) 0x2A, (byte) 0x92, (byte) 0xF4};
        byte[] b1 = new byte[]{(byte) 0xCB, (byte) 0x1C, (byte) 0xF8, (byte) 0xCE};
        byte[] c1 = new byte[]{(byte) 0x45, (byte) 0x81, (byte) 0x47, (byte) 0x2E};
        byte[] d1 = new byte[]{(byte) 0x58, (byte) 0x81, (byte) 0xC4, (byte) 0xBB};

        ChaCha20 cipher = new ChaCha20();
        cipher.quarterRound(a, b, c, d);
        System.out.println("Result for a: " + BinUtils.toHexString(a) + " [" + BinUtils.binArrayElementsCompare(a, 0, a1, 0, 4) + "]");
        System.out.println("Result for b: " + BinUtils.toHexString(b) + " [" + BinUtils.binArrayElementsCompare(b, 0, b1, 0, 4) + "]");
        System.out.println("Result for c: " + BinUtils.toHexString(c) + " [" + BinUtils.binArrayElementsCompare(c, 0, c1, 0, 4) + "]");
        System.out.println("Result for d: " + BinUtils.toHexString(d) + " [" + BinUtils.binArrayElementsCompare(d, 0, d1, 0, 4) + "]");
    }

    public static void fullCryptoTest() {
        byte[] key = {
            (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04,
            (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08, (byte) 0x09,
            (byte) 0x0a, (byte) 0x0b, (byte) 0x0c, (byte) 0x0d, (byte) 0x0e,
            (byte) 0x0f, (byte) 0x10, (byte) 0x11, (byte) 0x12, (byte) 0x13,
            (byte) 0x14, (byte) 0x15, (byte) 0x16, (byte) 0x17, (byte) 0x18,
            (byte) 0x19, (byte) 0x1a, (byte) 0x1b, (byte) 0x1c, (byte) 0x1d,
            (byte) 0x1e, (byte) 0x1f
        };

        byte[] nonce = {(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x4a, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00
        };

        byte[] ctr = {
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01
        };

        byte[] expectedFinalKeyStream = {
            (byte) 0x22, (byte) 0x4f, (byte) 0x51, (byte) 0xf3,
            (byte) 0x40, (byte) 0x1b, (byte) 0xd9, (byte) 0xe1,
            (byte) 0x2f, (byte) 0xde, (byte) 0x27, (byte) 0x6f,
            (byte) 0xb8, (byte) 0x63, (byte) 0x1d, (byte) 0xed,
            (byte) 0x8c, (byte) 0x13, (byte) 0x1f, (byte) 0x82,
            (byte) 0x3d, (byte) 0x2c, (byte) 0x06, (byte) 0xe2,
            (byte) 0x7e, (byte) 0x4f, (byte) 0xca, (byte) 0xec,
            (byte) 0x9e, (byte) 0xf3, (byte) 0xcf, (byte) 0x78,
            (byte) 0x8a, (byte) 0x3b, (byte) 0x0a, (byte) 0xa3,
            (byte) 0x72, (byte) 0x60, (byte) 0x0a, (byte) 0x92,
            (byte) 0xb5, (byte) 0x79, (byte) 0x74, (byte) 0xcd,
            (byte) 0xed, (byte) 0x2b, (byte) 0x93, (byte) 0x34,
            (byte) 0x79, (byte) 0x4c, (byte) 0xba, (byte) 0x40,
            (byte) 0xc6, (byte) 0x3e, (byte) 0x34, (byte) 0xcd,
            (byte) 0xea, (byte) 0x21, (byte) 0x2c, (byte) 0x4c,
            (byte) 0xf0, (byte) 0x7d, (byte) 0x41, (byte) 0xb7
        };

        byte[] expectedCipherText = {
            (byte) 0x6e, (byte) 0x2e, (byte) 0x35, (byte) 0x9a, (byte) 0x25,
            (byte) 0x68, (byte) 0xf9, (byte) 0x80, (byte) 0x41, (byte) 0xba,
            (byte) 0x07, (byte) 0x28, (byte) 0xdd, (byte) 0x0d, (byte) 0x69,
            (byte) 0x81, (byte) 0xe9, (byte) 0x7e, (byte) 0x7a, (byte) 0xec,
            (byte) 0x1d, (byte) 0x43, (byte) 0x60, (byte) 0xc2, (byte) 0x0a,
            (byte) 0x27, (byte) 0xaf, (byte) 0xcc, (byte) 0xfd, (byte) 0x9f,
            (byte) 0xae, (byte) 0x0b, (byte) 0xf9, (byte) 0x1b, (byte) 0x65,
            (byte) 0xc5, (byte) 0x52, (byte) 0x47, (byte) 0x33, (byte) 0xab,
            (byte) 0x8f, (byte) 0x59, (byte) 0x3d, (byte) 0xab, (byte) 0xcd,
            (byte) 0x62, (byte) 0xb3, (byte) 0x57, (byte) 0x16, (byte) 0x39,
            (byte) 0xd6, (byte) 0x24, (byte) 0xe6, (byte) 0x51, (byte) 0x52,
            (byte) 0xab, (byte) 0x8f, (byte) 0x53, (byte) 0x0c, (byte) 0x35,
            (byte) 0x9f, (byte) 0x08, (byte) 0x61, (byte) 0xd8
        };

        byte[] input = {
            (byte) 0x4c, (byte) 0x61, (byte) 0x64, (byte) 0x69, (byte) 0x65,
            (byte) 0x73, (byte) 0x20, (byte) 0x61, (byte) 0x6e, (byte) 0x64,
            (byte) 0x20, (byte) 0x47, (byte) 0x65, (byte) 0x6e, (byte) 0x74,
            (byte) 0x6c, (byte) 0x65, (byte) 0x6d, (byte) 0x65, (byte) 0x6e,
            (byte) 0x20, (byte) 0x6f, (byte) 0x66, (byte) 0x20, (byte) 0x74,
            (byte) 0x68, (byte) 0x65, (byte) 0x20, (byte) 0x63, (byte) 0x6c,
            (byte) 0x61, (byte) 0x73, (byte) 0x73, (byte) 0x20, (byte) 0x6f,
            (byte) 0x66, (byte) 0x20, (byte) 0x27, (byte) 0x39, (byte) 0x39,
            (byte) 0x3a, (byte) 0x20, (byte) 0x49, (byte) 0x66, (byte) 0x20,
            (byte) 0x49, (byte) 0x20, (byte) 0x63, (byte) 0x6f, (byte) 0x75,
            (byte) 0x6c, (byte) 0x64, (byte) 0x20, (byte) 0x6f, (byte) 0x66,
            (byte) 0x66, (byte) 0x65, (byte) 0x72, (byte) 0x20, (byte) 0x79,
            (byte) 0x6f, (byte) 0x75, (byte) 0x20, (byte) 0x6f
        };

        byte[] output = new byte[64];
        ChaCha20 cipher = new ChaCha20();
        boolean encrypted = cipher.encrypt(key, (short) 0, nonce, (short) 0, ctr, (short) 0, input, (short) 0, (short) input.length, output, (short) 0);
        boolean correctKeyStream = BinUtils.binArrayElementsCompare(expectedFinalKeyStream, 0, cipher.getCurrentKeyStreamState(), 0, expectedFinalKeyStream.length);
        boolean correctCipherText = BinUtils.binArrayElementsCompare(expectedCipherText, 0, output, 0, expectedCipherText.length);
        System.out.println("Output: \n" + BinUtils.toFormattedHexString(output, 16, 0));
        if (encrypted && correctKeyStream && correctCipherText) {
            System.out.println("ChaCha20 RFC7539 Test Encryption SUCCEEDED !");
        } else {
            System.out.println("ChaCha20 RFC7539 Test Encryption FAILED !");
        }

    }

    public static void main(String[] args) {
        fullCryptoTest();
    }

}
