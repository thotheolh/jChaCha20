/*
 * 32 bit Math in 8 bit format.
 */
package org.thotheolh.cryptolib.math;

import org.thotheolh.cryptolib.util.BinUtils;

/**
 *
 * @author Thotheolh
 */
public class MathUtil {

    private static byte add(byte x, byte y, byte[] result, short index) {
        byte c = 0;
        while (y != 0) {
            byte t = (byte) (x & y);
            c |= t;
            x = (byte) (x ^ y);
            y = (byte) (t << 1);
        }
        result[index] = x;
        return (byte) ((c & 0x80) != 0 ? 1 : 0);
    }

    private static byte add(byte a, byte b, byte c, byte[] result, short index) {
        byte carry = add(a, b, result, index);
        if (c > 0) {
            carry |= add(result[index], c, result, index);
        }
        return carry;
    }

    private static void add(byte[] a, short aOffset, byte[] b, short bOffset, byte[] result, short offset) {
        byte c = 0;
        c = add(a[(short) (aOffset + 3)], b[(short) (bOffset + 3)], c, result, (short) (offset + 3));
        c = add(a[(short) (aOffset + 2)], b[(short) (bOffset + 2)], c, result, (short) (offset + 2));
        c = add(a[(short) (aOffset + 1)], b[(short) (bOffset + 1)], c, result, (short) (offset + 1));
        c = add(a[aOffset], b[bOffset], c, result, offset);
    }

    public static void mod32Add(byte[] a, short aOffset, byte[] b, short bOffset, byte[] result, short offset) {
        add(a, aOffset, b, bOffset, result, offset);
        result[offset] &= 0xFF;
        result[(short) (offset + 1)] &= 0xFF;
        result[(short) (offset + 2)] &= 0xFF;
        result[(short) (offset + 3)] &= 0xFF;
    }

    public static void xor32(byte[] a, short aOffset, byte[] b, short bOffset, byte[] result, short offset) {
        result[offset] = (byte) (a[aOffset] ^ b[bOffset]);
        result[(short) (offset + 1)] = (byte) (a[(short) (aOffset + 1)] ^ b[(short) (bOffset + 1)]);
        result[(short) (offset + 2)] = (byte) (a[(short) (aOffset + 2)] ^ b[(short) (bOffset + 2)]);
        result[(short) (offset + 3)] = (byte) (a[(short) (aOffset + 3)] ^ b[(short) (bOffset + 3)]);
    }

    public static void rotl32(byte[] a, short offset, short amt, byte[] buff, short buffOffset) {
        byte normalizer;

        if (amt == 7) {
            normalizer = (byte) 0x80;

            if (((byte) a[offset] | (byte) 0x7F) != (byte) 0x7F) {
                buff[buffOffset] = (byte) (a[offset] >>> 1 ^ normalizer);
            } else {
                buff[buffOffset] = (byte) (a[offset] >>> 1);
            }

            if (((byte) a[(short) (offset + 1)] | (byte) 0x7F) != (byte) 0x7F) {
                a[offset] = (byte) ((a[offset] << 7) | (a[(short) (offset + 1)] >>> 1) ^ normalizer);
            } else {
                a[offset] = (byte) ((a[offset] << 7) | (a[(short) (offset + 1)] >>> 1));
            }

            if (((byte) a[(short) (offset + 2)] | (byte) 0x7F) != (byte) 0x7F) {
                a[(short) (offset + 1)] = (byte) ((a[(short) (offset + 1)] << 7) | ((a[(short) (offset + 2)] >>> 1) ^ normalizer));
            } else {
                a[(short) (offset + 1)] = (byte) ((a[(short) (offset + 1)] << 7) | ((a[(short) (offset + 2)] >>> 1)));
            }

            if (((byte) a[(short) (offset + 3)] | (byte) 0x7F) != (byte) 0x7F) {
                a[(short) (offset + 2)] = (byte) ((a[(short) (offset + 2)] << 7) | ((a[(short) (offset + 3)] >>> 1) ^ normalizer));
            } else {
                a[(short) (offset + 2)] = (byte) ((a[(short) (offset + 2)] << 7) | ((a[(short) (offset + 3)] >>> 1)));
            }

            a[(short) (offset + 3)] = (byte) ((a[(short) (offset + 3)] << 7) | buff[buffOffset]);

        } else if (amt == 8) {
            buff[buffOffset] = a[offset];
            a[offset] = a[(short) (offset + 1)];
            a[(short) (offset + 1)] = a[(short) (offset + 2)];
            a[(short) (offset + 2)] = a[(short) (offset + 3)];
            a[(short) (offset + 3)] = buff[offset];
        } else if (amt == 12) {
            buff[buffOffset] = a[offset];
            buff[(short) (buffOffset + 1)] = a[(short) (offset + 1)];
            normalizer = (byte) 0xF0;

            if (((byte) a[(short) (offset + 2)] | (byte) 0x7F) != (byte) 0x7F) {
                a[offset] = (byte) ((a[(short) (offset + 1)] << 4) ^ ((a[(short) (offset + 2)] >>> 4) ^ normalizer));
            } else {
                a[offset] = (byte) ((a[(short) (offset + 1)] << 4) ^ (a[(short) (offset + 2)] >>> 4));
            }

            if (((byte) a[(short) (offset + 3)] | (byte) 0x7F) != (byte) 0x7F) {
                a[(short) (offset + 1)] = (byte) ((a[(short) (offset + 2)] << 4) ^ ((a[(short) (offset + 3)] >>> 4) ^ normalizer));
            } else {
                a[(short) (offset + 1)] = (byte) ((a[(short) (offset + 2)] << 4) ^ (a[(short) (offset + 3)] >>> 4));
            }

            if (((byte) buff[offset] | (byte) 0x7F) != (byte) 0x7F) {
                a[(short) (offset + 2)] = (byte) ((a[(short) (offset + 3)] << 4) ^ ((buff[offset] >>> 4) ^ normalizer));
            } else {
                a[(short) (offset + 2)] = (byte) ((a[(short) (offset + 3)] << 4) ^ (buff[offset] >>> 4));
            }

            if (((byte) buff[(short) (offset + 1)] | (byte) 0x7F) != (byte) 0x7F) {
                a[(short) (offset + 3)] = (byte) ((buff[offset] << 4) ^ ((buff[(short) (offset + 1)] >>> 4) ^ normalizer));
            } else {
                a[(short) (offset + 3)] = (byte) ((buff[offset] << 4) ^ (buff[(short) (offset + 1)] >>> 4));
            }

        } else if (amt == 16) {
            buff[buffOffset] = a[offset];
            buff[(short) (buffOffset + 1)] = a[(short) (offset + 1)];
            a[offset] = a[(short) (offset + 2)];
            a[(short) (offset + 1)] = a[(short) (offset + 3)];
            a[(short) (offset + 2)] = buff[offset];
            a[(short) (offset + 3)] = buff[(short) (offset + 1)];
        }
    }

    public static void main(String[] args) {
        byte[] a = new byte[]{(byte) 0x11, (byte) 0x11, (byte) 0x11, (byte) 0x11};
        byte[] b = new byte[]{(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04};
        byte[] c = new byte[]{(byte) 0x77, (byte) 0x77, (byte) 0x77, (byte) 0x77};
        byte[] d = new byte[]{(byte) 0x01, (byte) 0x23, (byte) 0x45, (byte) 0x67};
        byte[] mod32TestAnswer = new byte[]{(byte) 0x78, (byte) 0x9A, (byte) 0xBC, (byte) 0xDE};
        byte[] xor32TestAnswer = new byte[]{(byte) 0x79, (byte) 0x98, (byte) 0xBF, (byte) 0xDA};
        byte[] rotl32TestAnswer = new byte[]{(byte) 0xCC, (byte) 0x5F, (byte) 0xED, (byte) 0x3C};
        byte[] buff = new byte[]{0x00, 0x00, 0x00, 0x00};
        byte[] res = new byte[4];
        int passed = 0;

        // ChaCha Algorithm Math Test
        System.out.println("Begin Mod 32 Test ...");

        mod32Add(c, (short) 0, d, (short) 0, c, (short) 0);

        System.out.println("Mod 32 Add Result: " + BinUtils.toHexString(c));

        if (BinUtils.binArrayElementsCompare(c, 0, mod32TestAnswer, 0, 4)) {
            System.out.println("Mod 32 Test [OK]");
            passed++;
        } else {
            System.out.println("Mod 32 Test [FAIL]");
        }

        System.out.println("Begin Xor 32 Test ...");

        xor32(b, (short) 0, c, (short) 0, b, (short) 0);

        System.out.println("Xor 32 Result: " + BinUtils.toHexString(b));

        if (BinUtils.binArrayElementsCompare(b, 0, xor32TestAnswer, 0, 4)) {
            System.out.println("Xor 32 Test [OK]");
            passed++;
        } else {
            System.out.println("Xor 32 Test [FAIL]");
        }

        System.out.println("Begin ROTL 32 Test ...");

        rotl32(b, (short) 0, (short) 7, buff, (short) 0);
        System.out.println("ROTL 32/7 Result: " + BinUtils.toHexString(b));

        if (BinUtils.binArrayElementsCompare(b, 0, rotl32TestAnswer, 0, 4)) {
            System.out.println("ROTL 32 Test [OK]");
            passed++;
        } else {
            System.out.println("ROTL 32 Test [FAIL]");
        }

        if (passed == 3) {
            System.out.println("Math Test [OK]");
        } else {
            System.out.println("Math Test [FAIL]");
        }
    }
}
