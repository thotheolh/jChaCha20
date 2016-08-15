/*
 * 20 rounds of ChaCha20 using only 8 bit maths for embedded purposes. Uses 
 * RFC7539 Standard setup of key, nonce and counter (32 bytes, 12 bytes, 
 * 4 bytes) accordingly.
 *
 */
package org.thotheolh.cryptolib.cipher;

import org.thotheolh.cryptolib.util.BinUtils;
import org.thotheolh.cryptolib.math.MathUtil;

/**
 *
 * @author Thotheolh
 */
public class ChaCha20 {

    private byte[] matrix0 = new byte[4];
    private byte[] matrix1 = new byte[4];
    private byte[] matrix2 = new byte[4];
    private byte[] matrix3 = new byte[4];
    private byte[] matrix4 = new byte[4];
    private byte[] matrix5 = new byte[4];
    private byte[] matrix6 = new byte[4];
    private byte[] matrix7 = new byte[4];
    private byte[] matrix8 = new byte[4];
    private byte[] matrix9 = new byte[4];
    private byte[] matrix10 = new byte[4];
    private byte[] matrix11 = new byte[4];
    private byte[] matrix12 = new byte[4];
    private byte[] matrix13 = new byte[4];
    private byte[] matrix14 = new byte[4];
    private byte[] matrix15 = new byte[4];
    private byte[] buffer = new byte[4];
    private byte[] inputInitState = new byte[64];

    public ChaCha20() {
    }

    /**
     * ChaCha QuarterRound Round Function in sequence.
     * a += b; d ^= a; d <<<= 16;
     * c += d; b ^= c; b <<<= 12;
     * a += b; d ^= a; d <<<= 8;
     * c += d; b ^= c; b <<<= 7;
     *
     * @param a
     * @param b
     * @param c
     * @param d
     */
    public void quarterRound(byte[] a, byte[] b, byte[] c, byte[] d) {
        // a += b;
        // System.out.println("Mod 32 Add: " + BinUtils.toHexString(a) + " , " + BinUtils.toHexString(b));
        MathUtil.mod32Add(a, (short) 0, b, (short) 0, a, (short) 0);
        // System.out.println(" = " + BinUtils.toHexString(a));

        // d ^= a;
        // System.out.println("Mod 32 Xor: " + BinUtils.toHexString(d) + " , " + BinUtils.toHexString(a));
        MathUtil.xor32(d, (short) 0, a, (short) 0, d, (short) 0);
        // System.out.println(" = " + BinUtils.toHexString(d));

        // d <<<= 16;
        // System.out.println("Mod 32 ROTL-16: " + BinUtils.toHexString(d));
        MathUtil.rotl32(d, (short) 0, (short) 16, buffer, (short) 0);
        // System.out.println(" = " + BinUtils.toHexString(d));

        // c += d;
        // System.out.println("Mod 32 Add: " + BinUtils.toHexString(c) + " + " + BinUtils.toHexString(d));
        MathUtil.mod32Add(c, (short) 0, d, (short) 0, c, (short) 0);
        // System.out.println(" = " + BinUtils.toHexString(c));

        // b ^= c;
        // System.out.println("Mod 32 Xor: " + BinUtils.toHexString(b) + " + " + BinUtils.toHexString(c));
        MathUtil.xor32(b, (short) 0, c, (short) 0, b, (short) 0);
        // System.out.println(" = " + BinUtils.toHexString(b));

        // b <<<= 12;
        // System.out.println("Mod 32 ROTL-12: " + BinUtils.toHexString(b));
        MathUtil.rotl32(b, (short) 0, (short) 12, buffer, (short) 0);
        // System.out.println(" = " + BinUtils.toHexString(b));

        // a += b;
        // System.out.println("Mod 32 Add: " + BinUtils.toHexString(a) + " + " + BinUtils.toHexString(b));
        MathUtil.mod32Add(a, (short) 0, b, (short) 0, a, (short) 0);
        // System.out.println(" = " + BinUtils.toHexString(a));

        // d ^= a;
        // System.out.println("Mod 32 Xor: " + BinUtils.toHexString(d) + " + " + BinUtils.toHexString(a));
        MathUtil.xor32(d, (short) 0, a, (short) 0, d, (short) 0);
        // System.out.println(" = " + BinUtils.toHexString(d));

        // d <<<= 8;
        // System.out.println("Mod 32 ROTL-8: " + BinUtils.toHexString(d));
        MathUtil.rotl32(d, (short) 0, (short) 8, buffer, (short) 0);
        // System.out.println(" = " + BinUtils.toHexString(d));

        // c += d;
        // System.out.println("Mod 32 Add: " + BinUtils.toHexString(c) + " + " + BinUtils.toHexString(d));
        MathUtil.mod32Add(c, (short) 0, d, (short) 0, c, (short) 0);
        // System.out.println(" = " + BinUtils.toHexString(c));

        // b ^= c;
        // System.out.println("Mod 32 Xor: " + BinUtils.toHexString(b) + " + " + BinUtils.toHexString(c));
        MathUtil.xor32(b, (short) 0, c, (short) 0, b, (short) 0);
        // System.out.println(" = " + BinUtils.toHexString(b));

        // b <<<= 7;
        // System.out.println("Mod 32 ROTL-7: " + BinUtils.toHexString(b));
        MathUtil.rotl32(b, (short) 0, (short) 7, buffer, (short) 0);
        // System.out.println(" = " + BinUtils.toHexString(b));
    }

    private void littleEndian(byte[] data, short dataOffset, byte[] buff, short buffOffset) {
        System.arraycopy(data, dataOffset, buff, buffOffset, (short) 4);
        data[dataOffset] = buff[buffOffset + 3];
        data[dataOffset + 1] = buff[buffOffset + 2];
        data[dataOffset + 2] = buff[buffOffset + 1];
        data[dataOffset + 3] = buff[buffOffset];
    }

    private boolean init(byte[] key, short keyOffset, byte[] nonce, short nonceOffset, byte[] counter, short ctrOffset) {
        if (((key.length - keyOffset) >= 32) && ((nonce.length - nonceOffset) >= 12) && ((counter.length - ctrOffset) >= 4)) {
            // Set constant into matrcies
            matrix0[0] = (byte) 0x61;
            matrix0[1] = (byte) 0x70;
            matrix0[2] = (byte) 0x78;
            matrix0[3] = (byte) 0x65;
            matrix1[0] = (byte) 0x33;
            matrix1[1] = (byte) 0x20;
            matrix1[2] = (byte) 0x64;
            matrix1[3] = (byte) 0x6E;
            matrix2[0] = (byte) 0x79;
            matrix2[1] = (byte) 0x62;
            matrix2[2] = (byte) 0x2D;
            matrix2[3] = (byte) 0x32;
            matrix3[0] = (byte) 0x6B;
            matrix3[1] = (byte) 0x20;
            matrix3[2] = (byte) 0x65;
            matrix3[3] = (byte) 0x74;

            // Set constant into inputInitState
            inputInitState[0] = (byte) 0x61;
            inputInitState[1] = (byte) 0x70;
            inputInitState[2] = (byte) 0x78;
            inputInitState[3] = (byte) 0x65;
            inputInitState[4] = (byte) 0x33;
            inputInitState[5] = (byte) 0x20;
            inputInitState[6] = (byte) 0x64;
            inputInitState[7] = (byte) 0x6E;
            inputInitState[8] = (byte) 0x79;
            inputInitState[9] = (byte) 0x62;
            inputInitState[10] = (byte) 0x2D;
            inputInitState[11] = (byte) 0x32;
            inputInitState[12] = (byte) 0x6B;
            inputInitState[13] = (byte) 0x20;
            inputInitState[14] = (byte) 0x65;
            inputInitState[15] = (byte) 0x74;

            // Set key into matrices
            System.arraycopy(key, keyOffset, matrix4, 0, 4);
            System.arraycopy(key, keyOffset + 4, matrix5, 0, 4);
            System.arraycopy(key, keyOffset + 8, matrix6, 0, 4);
            System.arraycopy(key, keyOffset + 12, matrix7, 0, 4);
            System.arraycopy(key, keyOffset + 16, matrix8, 0, 4);
            System.arraycopy(key, keyOffset + 20, matrix9, 0, 4);
            System.arraycopy(key, keyOffset + 24, matrix10, 0, 4);
            System.arraycopy(key, keyOffset + 28, matrix11, 0, 4);
            littleEndian(matrix4, (short) 0, buffer, (short) 0);
            littleEndian(matrix5, (short) 0, buffer, (short) 0);
            littleEndian(matrix6, (short) 0, buffer, (short) 0);
            littleEndian(matrix7, (short) 0, buffer, (short) 0);
            littleEndian(matrix8, (short) 0, buffer, (short) 0);
            littleEndian(matrix9, (short) 0, buffer, (short) 0);
            littleEndian(matrix10, (short) 0, buffer, (short) 0);
            littleEndian(matrix11, (short) 0, buffer, (short) 0);

            // Set key into inputInitState
            System.arraycopy(matrix4, (short) 0, inputInitState, 16, 4);
            System.arraycopy(matrix5, (short) 0, inputInitState, 20, 4);
            System.arraycopy(matrix6, (short) 0, inputInitState, 24, 4);
            System.arraycopy(matrix7, (short) 0, inputInitState, 28, 4);
            System.arraycopy(matrix8, (short) 0, inputInitState, 32, 4);
            System.arraycopy(matrix9, (short) 0, inputInitState, 36, 4);
            System.arraycopy(matrix10, (short) 0, inputInitState, 40, 4);
            System.arraycopy(matrix11, (short) 0, inputInitState, 44, 4);

            // Set counter into matrices
            System.arraycopy(counter, ctrOffset, matrix12, 0, 4);

            // Set counter into inputInitState
            System.arraycopy(counter, ctrOffset, inputInitState, 48, 4);

            // Set nonce into matrices
            System.arraycopy(nonce, nonceOffset, matrix13, 0, 4);
            System.arraycopy(nonce, nonceOffset + 4, matrix14, 0, 4);
            System.arraycopy(nonce, nonceOffset + 8, matrix15, 0, 4);
            littleEndian(matrix13, (short) 0, buffer, (short) 0);
            littleEndian(matrix14, (short) 0, buffer, (short) 0);
            littleEndian(matrix15, (short) 0, buffer, (short) 0);

            // Set nonce into inputInitState
            System.arraycopy(matrix13, (short) 0, inputInitState, 52, 4);
            System.arraycopy(matrix14, (short) 0, inputInitState, 56, 4);
            System.arraycopy(matrix15, (short) 0, inputInitState, 60, 4);
            return true;
        }
        return false;
    }

    public boolean encrypt(byte[] key, short keyOffset, byte[] nonce,
            short nonceOffset, byte[] counter, short ctrOffset, byte[] input,
            short inOffset, short length, byte[] output, short outOffset) {

        // Setup internal state
        if (init(key, keyOffset, nonce, nonceOffset, counter, ctrOffset)) {
            if (length <= 64) {

                System.out.println("Loaded Matrices Before Quarter Rounds: ");
                dumpMatrices();

                // Quarter Round 1 -- 20 Iterations is actually 10 rounds
                quarterRound(matrix0, matrix4, matrix8, matrix12);
                quarterRound(matrix1, matrix5, matrix9, matrix13);
                quarterRound(matrix2, matrix6, matrix10, matrix14);
                quarterRound(matrix3, matrix7, matrix11, matrix15);
                quarterRound(matrix0, matrix5, matrix10, matrix15);
                quarterRound(matrix1, matrix6, matrix11, matrix12);
                quarterRound(matrix2, matrix7, matrix8, matrix13);
                quarterRound(matrix3, matrix4, matrix9, matrix14);

                //System.out.println("Quarter Round 1 done ...");
                // Quarter Round 2
                quarterRound(matrix0, matrix4, matrix8, matrix12);
                quarterRound(matrix1, matrix5, matrix9, matrix13);
                quarterRound(matrix2, matrix6, matrix10, matrix14);
                quarterRound(matrix3, matrix7, matrix11, matrix15);
                quarterRound(matrix0, matrix5, matrix10, matrix15);
                quarterRound(matrix1, matrix6, matrix11, matrix12);
                quarterRound(matrix2, matrix7, matrix8, matrix13);
                quarterRound(matrix3, matrix4, matrix9, matrix14);

                //System.out.println("Quarter Round 2 done ...");
                // Quarter Round 3
                quarterRound(matrix0, matrix4, matrix8, matrix12);
                quarterRound(matrix1, matrix5, matrix9, matrix13);
                quarterRound(matrix2, matrix6, matrix10, matrix14);
                quarterRound(matrix3, matrix7, matrix11, matrix15);
                quarterRound(matrix0, matrix5, matrix10, matrix15);
                quarterRound(matrix1, matrix6, matrix11, matrix12);
                quarterRound(matrix2, matrix7, matrix8, matrix13);
                quarterRound(matrix3, matrix4, matrix9, matrix14);

                //System.out.println("Quarter Round 3 done ...");
                // Quarter Round 4
                quarterRound(matrix0, matrix4, matrix8, matrix12);
                quarterRound(matrix1, matrix5, matrix9, matrix13);
                quarterRound(matrix2, matrix6, matrix10, matrix14);
                quarterRound(matrix3, matrix7, matrix11, matrix15);
                quarterRound(matrix0, matrix5, matrix10, matrix15);
                quarterRound(matrix1, matrix6, matrix11, matrix12);
                quarterRound(matrix2, matrix7, matrix8, matrix13);
                quarterRound(matrix3, matrix4, matrix9, matrix14);

                //System.out.println("Quarter Round 4 done ...");
                // Quarter Round 5
                quarterRound(matrix0, matrix4, matrix8, matrix12);
                quarterRound(matrix1, matrix5, matrix9, matrix13);
                quarterRound(matrix2, matrix6, matrix10, matrix14);
                quarterRound(matrix3, matrix7, matrix11, matrix15);
                quarterRound(matrix0, matrix5, matrix10, matrix15);
                quarterRound(matrix1, matrix6, matrix11, matrix12);
                quarterRound(matrix2, matrix7, matrix8, matrix13);
                quarterRound(matrix3, matrix4, matrix9, matrix14);

                //System.out.println("Quarter Round 5 done ...");
                // Quarter Round 6
                quarterRound(matrix0, matrix4, matrix8, matrix12);
                quarterRound(matrix1, matrix5, matrix9, matrix13);
                quarterRound(matrix2, matrix6, matrix10, matrix14);
                quarterRound(matrix3, matrix7, matrix11, matrix15);
                quarterRound(matrix0, matrix5, matrix10, matrix15);
                quarterRound(matrix1, matrix6, matrix11, matrix12);
                quarterRound(matrix2, matrix7, matrix8, matrix13);
                quarterRound(matrix3, matrix4, matrix9, matrix14);

                //System.out.println("Quarter Round 6 done ...");
                // Quarter Round 7
                quarterRound(matrix0, matrix4, matrix8, matrix12);
                quarterRound(matrix1, matrix5, matrix9, matrix13);
                quarterRound(matrix2, matrix6, matrix10, matrix14);
                quarterRound(matrix3, matrix7, matrix11, matrix15);
                quarterRound(matrix0, matrix5, matrix10, matrix15);
                quarterRound(matrix1, matrix6, matrix11, matrix12);
                quarterRound(matrix2, matrix7, matrix8, matrix13);
                quarterRound(matrix3, matrix4, matrix9, matrix14);

                //System.out.println("Quarter Round 7 done ...");
                // Quarter Round 8
                quarterRound(matrix0, matrix4, matrix8, matrix12);
                quarterRound(matrix1, matrix5, matrix9, matrix13);
                quarterRound(matrix2, matrix6, matrix10, matrix14);
                quarterRound(matrix3, matrix7, matrix11, matrix15);
                quarterRound(matrix0, matrix5, matrix10, matrix15);
                quarterRound(matrix1, matrix6, matrix11, matrix12);
                quarterRound(matrix2, matrix7, matrix8, matrix13);
                quarterRound(matrix3, matrix4, matrix9, matrix14);

                //System.out.println("Quarter Round 8 done ...");
                // Quarter Round 9
                quarterRound(matrix0, matrix4, matrix8, matrix12);
                quarterRound(matrix1, matrix5, matrix9, matrix13);
                quarterRound(matrix2, matrix6, matrix10, matrix14);
                quarterRound(matrix3, matrix7, matrix11, matrix15);
                quarterRound(matrix0, matrix5, matrix10, matrix15);
                quarterRound(matrix1, matrix6, matrix11, matrix12);
                quarterRound(matrix2, matrix7, matrix8, matrix13);
                quarterRound(matrix3, matrix4, matrix9, matrix14);

                //System.out.println("Quarter Round 9 done ...");
                // Quarter Round 10
                quarterRound(matrix0, matrix4, matrix8, matrix12);
                quarterRound(matrix1, matrix5, matrix9, matrix13);
                quarterRound(matrix2, matrix6, matrix10, matrix14);
                quarterRound(matrix3, matrix7, matrix11, matrix15);
                quarterRound(matrix0, matrix5, matrix10, matrix15);
                quarterRound(matrix1, matrix6, matrix11, matrix12);
                quarterRound(matrix2, matrix7, matrix8, matrix13);
                quarterRound(matrix3, matrix4, matrix9, matrix14);

                //System.out.println("Quarter Round 10 done ...");
                System.out.println("Loaded Matrices After Quarter Rounds: ");
                dumpMatrices();

                // Update inputInitState by mod32Add matrices
                System.out.println("Original Keystream: ");
                dumpKeyStream();

                MathUtil.mod32Add(inputInitState, (short) 0, matrix0, (short) 0, inputInitState, (short) 0);
                MathUtil.mod32Add(inputInitState, (short) 4, matrix1, (short) 0, inputInitState, (short) 4);
                MathUtil.mod32Add(inputInitState, (short) 8, matrix2, (short) 0, inputInitState, (short) 8);
                MathUtil.mod32Add(inputInitState, (short) 12, matrix3, (short) 0, inputInitState, (short) 12);
                MathUtil.mod32Add(inputInitState, (short) 16, matrix4, (short) 0, inputInitState, (short) 16);
                MathUtil.mod32Add(inputInitState, (short) 20, matrix5, (short) 0, inputInitState, (short) 20);
                MathUtil.mod32Add(inputInitState, (short) 24, matrix6, (short) 0, inputInitState, (short) 24);
                MathUtil.mod32Add(inputInitState, (short) 28, matrix7, (short) 0, inputInitState, (short) 28);
                MathUtil.mod32Add(inputInitState, (short) 32, matrix8, (short) 0, inputInitState, (short) 32);
                MathUtil.mod32Add(inputInitState, (short) 36, matrix9, (short) 0, inputInitState, (short) 36);
                MathUtil.mod32Add(inputInitState, (short) 40, matrix10, (short) 0, inputInitState, (short) 40);
                MathUtil.mod32Add(inputInitState, (short) 44, matrix11, (short) 0, inputInitState, (short) 44);
                MathUtil.mod32Add(inputInitState, (short) 48, matrix12, (short) 0, inputInitState, (short) 48);
                MathUtil.mod32Add(inputInitState, (short) 52, matrix13, (short) 0, inputInitState, (short) 52);
                MathUtil.mod32Add(inputInitState, (short) 56, matrix14, (short) 0, inputInitState, (short) 56);
                MathUtil.mod32Add(inputInitState, (short) 60, matrix15, (short) 0, inputInitState, (short) 60);

                System.out.println("After Mixing Original Keystream with Matrices: ");
                dumpKeyStream();

                littleEndian(inputInitState, (short) 0, buffer, (short) 0);
                littleEndian(inputInitState, (short) 4, buffer, (short) 0);
                littleEndian(inputInitState, (short) 8, buffer, (short) 0);
                littleEndian(inputInitState, (short) 12, buffer, (short) 0);
                littleEndian(inputInitState, (short) 16, buffer, (short) 0);
                littleEndian(inputInitState, (short) 20, buffer, (short) 0);
                littleEndian(inputInitState, (short) 24, buffer, (short) 0);
                littleEndian(inputInitState, (short) 28, buffer, (short) 0);
                littleEndian(inputInitState, (short) 32, buffer, (short) 0);
                littleEndian(inputInitState, (short) 36, buffer, (short) 0);
                littleEndian(inputInitState, (short) 40, buffer, (short) 0);
                littleEndian(inputInitState, (short) 44, buffer, (short) 0);
                littleEndian(inputInitState, (short) 48, buffer, (short) 0);
                littleEndian(inputInitState, (short) 52, buffer, (short) 0);
                littleEndian(inputInitState, (short) 56, buffer, (short) 0);
                littleEndian(inputInitState, (short) 60, buffer, (short) 0);

                System.out.println("After serializing state: ");
                dumpKeyStream();

                for (short i = 0; i < 64; i++) {
                    if (length > 0) {
                        output[outOffset + i] = (byte) (input[inOffset + i] ^ inputInitState[i]);
                        length--;
                    } else {
                        break;
                    }
                }

                if (length == 0) {
                    return true;
                }
            }
        }
        return false;
    }

    public boolean decrypt(byte[] key, short keyOffset, byte[] nonce,
            short nonceOffset, byte[] counter, short ctrOffset, byte[] input,
            short inOffset, short length, byte[] output, short outOffset) {
        return encrypt(key, keyOffset, nonce, nonceOffset, counter, ctrOffset, input, inOffset, length, output, outOffset);
    }
    
    public byte[] getCurrentKeyStreamState() {
        return inputInitState;
    }

    public void dumpMatrices() {
        System.out.print(BinUtils.toHexString(matrix0));
        System.out.print(" ");
        System.out.print(BinUtils.toHexString(matrix1));
        System.out.print(" ");
        System.out.print(BinUtils.toHexString(matrix2));
        System.out.print(" ");
        System.out.println(BinUtils.toHexString(matrix3));
        System.out.print(BinUtils.toHexString(matrix4));
        System.out.print(" ");
        System.out.print(BinUtils.toHexString(matrix5));
        System.out.print(" ");
        System.out.print(BinUtils.toHexString(matrix6));
        System.out.print(" ");
        System.out.println(BinUtils.toHexString(matrix7));
        System.out.print(BinUtils.toHexString(matrix8));
        System.out.print(" ");
        System.out.print(BinUtils.toHexString(matrix9));
        System.out.print(" ");
        System.out.print(BinUtils.toHexString(matrix10));
        System.out.print(" ");
        System.out.println(BinUtils.toHexString(matrix11));
        System.out.print(BinUtils.toHexString(matrix12));
        System.out.print(" ");
        System.out.print(BinUtils.toHexString(matrix13));
        System.out.print(" ");
        System.out.print(BinUtils.toHexString(matrix14));
        System.out.print(" ");
        System.out.print(BinUtils.toHexString(matrix15));
        System.out.println("\n");
    }

    public void dumpKeyStream() {
        System.out.println("Keystream: \n" + BinUtils.toFormattedHexString(inputInitState, 16, 0));
    }
}
