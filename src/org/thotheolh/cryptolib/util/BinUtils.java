/*
 * Binary Utility Tools.
 */
package org.thotheolh.cryptolib.util;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Thotheolh
 */
public class BinUtils {

    public static String toHexString(byte[] bytes) {
        char[] hexArray = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    public static String toFormattedHexString(byte[] bytes, int column, int whitespace) {
        StringBuffer strb = new StringBuffer();
        char[] hexArray = "0123456789ABCDEF".toCharArray();
        int wordCtr = 0;
        int wsCtr = 0;
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            strb.append(hexArray[v >>> 4]);
            strb.append(hexArray[v & 0x0F]);
            wordCtr++;
            if (wordCtr == column) {
                strb.append("\r\n");
                if (whitespace > 0) {
                    wsCtr = whitespace;
                    while (wsCtr > 0) {
                        strb.append(" ");
                        wsCtr--;
                    }
                }
                wordCtr = 0;
            }
        }
        return strb.toString();
    }

    public static String toAsciiString(byte[] byteStr) {
        try {
            return new String(byteStr, "UTF-8");
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(BinUtils.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    public static String toFormattedAsciiString(byte[] byteStr, int row) {
        StringBuffer strb;
        try {
            return new String(byteStr, "UTF-8");
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(BinUtils.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    public static boolean binArrayElementsCompare(byte[] srcArray, int srcOffset, byte[] destArray, int destOffset, int length) {
        boolean isMatch = true;
        if ((srcArray != null) && (destArray != null)) {
            for (int i = 0; i < length; i++) {
                if (srcArray[srcOffset + i] != destArray[destOffset + i]) {
                    isMatch = false;
                }
            }
        } else {
            isMatch = false;
        }
        return isMatch;
    }

    public static byte[] toBytes(BigInteger bigInt, int expectedSize) {
        byte[] tempArray = bigInt.toByteArray();
        byte[] resArray = new byte[expectedSize];
        if (tempArray.length > expectedSize) {
            System.arraycopy(tempArray, (tempArray.length - expectedSize), resArray, 0, expectedSize);
            return resArray;
        } else {
            return tempArray;
        }
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    public static byte intToByte(int i) {
        if (i < 255) {
            return (byte) (i & 0xFF);
        } else {
            throw new NumberFormatException("Integer is more than 255 !");
        }
    }
}
