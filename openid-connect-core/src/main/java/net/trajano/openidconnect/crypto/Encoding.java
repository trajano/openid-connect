package net.trajano.openidconnect.crypto;

import static net.trajano.openidconnect.internal.CharSets.US_ASCII;
import static net.trajano.openidconnect.internal.CharSets.UTF8;

import java.math.BigInteger;

/**
 * base64url implementation.
 *
 * @author Archimedes Trajano
 */
public final class Encoding {

    /**
     * Decoding map.
     */
    private static final byte[] DECODE_MAP;

    /**
     * Encoding map.
     */
    private static final char[] ENCODE_MAP = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".toCharArray();

    static {
        DECODE_MAP = new byte[128];
        for (byte b = 0; b < 64; ++b) {
            DECODE_MAP[ENCODE_MAP[b]] = b;
        }
        DECODE_MAP['+'] = 62;
        DECODE_MAP['/'] = 63;
    }

    /**
     * Encodes bytes in a buffer into a Base64 string.
     *
     * @param bytes
     *            bytes buffer
     * @param offset
     *            offset
     * @param length
     *            number of bytes to encode
     * @return Base64Url string
     */
    public static String base64Encode(final byte[] bytes,
            final int offset,
            final int length,
            final boolean padding) {

        final StringBuilder buffer = new StringBuilder(length * 3);
        for (int i = offset; i < offset + length; i += 3) {
            // p's are the segments for each byte. For every triple there are 6
            // segments
            int p0 = bytes[i] & 0xFC;
            p0 >>= 2;

        int p1 = bytes[i] & 0x03;
        p1 <<= 4;

        int p2;
        int p3;
        if (i + 1 < offset + length) {
            p2 = bytes[i + 1] & 0xF0;
            p2 >>= 4;
        p3 = bytes[i + 1] & 0x0F;
        p3 <<= 2;
        } else {
            p2 = 0;
            p3 = 0;
        }
        int p4;
        int p5;
        if (i + 2 < offset + length) {
            p4 = bytes[i + 2] & 0xC0;
            p4 >>= 6;
        p5 = bytes[i + 2] & 0x3F;
        } else {
            p4 = 0;
            p5 = 0;
        }

        if (i + 2 < offset + length) {
            buffer.append(ENCODE_MAP[p0]);
            buffer.append(ENCODE_MAP[p1 | p2]);
            buffer.append(ENCODE_MAP[p3 | p4]);
            buffer.append(ENCODE_MAP[p5]);
        } else if (i + 1 < offset + length) {
            buffer.append(ENCODE_MAP[p0]);
            buffer.append(ENCODE_MAP[p1 | p2]);
            buffer.append(ENCODE_MAP[p3]);
            if (padding) {
                buffer.append('=');
            }
        } else {
            buffer.append(ENCODE_MAP[p0]);
            buffer.append(ENCODE_MAP[p1 | p2]);
            if (padding) {
                buffer.append("==");
            }
        }
        }
        return buffer.toString();
    }

    /**
     * Encodes bytes into a base64 string as UTF8
     *
     * @param bytes
     *            bytes to encode
     * @return Base64 string
     */
    public static String base64Encode(final String s) {

        return base64Encode(s.getBytes(UTF8), 0, s.getBytes(UTF8).length, true);
    }

    /**
     * Encodes a US-ASCII string.
     *
     * @param s
     *            string to encode
     * @return Base64 string
     */
    public static String base64EncodeAscii(final String s) {

        return base64urlEncode(s.getBytes(US_ASCII));
    }

    /**
     * Encodes Base64urlUInt. The representation of a positive or zero integer
     * value as the base64url encoding of the value's unsigned big endian
     * representation as an octet sequence. The octet sequence MUST utilize the
     * minimum number of octets needed to represent the value. Zero is
     * represented as BASE64URL(single zero-valued octet), which is "AA".
     */
    public static String base64EncodeUint(final BigInteger v) {

        return base64urlEncode(v.toByteArray());
    }

    /**
     * Decodes a base64 or base64url string.
     *
     * @param base64String
     *            base64 string
     * @return bytes
     */
    public static byte[] base64urlDecode(final String base64String) {

        final byte[] buffer = new byte[base64urlDecodeLength(base64String)];
        base64urlDecode(base64String, buffer, 0);
        return buffer;
    }

    /**
     * Decodes a base64 string to a buffer.
     *
     * @param base64String
     *            base64 string
     * @param buffer
     *            buffer to fill
     * @param offset
     *            offset
     * @return amount of bytes decoded.
     */
    public static int base64urlDecode(final String base64String,
            final byte[] buffer,
            final int offset) {

        int p = 0;
        final byte[] base64Chars = base64String.getBytes();
        for (int i = 0; i < base64Chars.length; ++i) {
            if (i % 4 == 0) {
                buffer[offset + i - p] = (byte) (DECODE_MAP[base64Chars[i]] << 2);
            } else if (i % 4 == 1 && offset + i - p - 1 < buffer.length) {
                buffer[offset + i - p - 1] |= DECODE_MAP[base64Chars[i]] >> 4;
            if (offset + i - p < buffer.length) {
                buffer[offset + i - p] = (byte) (DECODE_MAP[base64Chars[i]] << 4);
            }
            } else if (i % 4 == 2 && offset + i - p - 1 < buffer.length) {
                buffer[offset + i - p - 1] |= DECODE_MAP[base64Chars[i]] >>> 2;
                if (offset + i - p < buffer.length) {
                    buffer[offset + i - p] = (byte) (DECODE_MAP[base64Chars[i]] << 6);
                }
            } else if (i % 4 == 3 && offset + i - p - 1 < buffer.length) {
                buffer[offset + i - p - 1] |= DECODE_MAP[base64Chars[i]];
                p++;
            }
        }
        return base64urlDecodeLength(base64String);
    }

    /**
     * Gets the byte length of the decoded text.
     *
     * @param base64String
     *            Base64 string
     * @return byte length of the decoded text.
     */
    public static int base64urlDecodeLength(final String base64String) {

        final int originalLength = base64String.length();
        if (originalLength == 0) {
            return 0;
        } else if (base64String.charAt(originalLength - 2) == '=') {
            return (originalLength - 2) * 3 / 4;
        } else if (base64String.charAt(originalLength - 1) == '=') {
            return (originalLength - 1) * 3 / 4;
        } else {
            return originalLength * 3 / 4;
        }
    }

    public static String base64urlDecodeToString(final String encoded) {

        return new String(base64urlDecode(encoded), UTF8);
    }

    /**
     * Decodes Base64urlUInt. The representation of a positive or zero integer
     * value as the base64url encoding of the value's unsigned big endian
     * representation as an octet sequence. The octet sequence MUST utilize the
     * minimum number of octets needed to represent the value. Zero is
     * represented as BASE64URL(single zero-valued octet), which is "AA".
     */
    public static BigInteger base64urlDecodeUint(final String s) {

        return new BigInteger(1, base64urlDecode(s));
    }

    /**
     * Encodes bytes into a base64url string.
     *
     * @param bytes
     *            bytes to encode
     * @return Base64 string
     */
    public static String base64urlEncode(final byte[] bytes) {

        return base64Encode(bytes, 0, bytes.length, false);
    }

    public static String base64urlEncode(final byte[] bytes,
            final int offset,
            final int len) {

        return base64Encode(bytes, offset, len, false);
    }

    /**
     * Encodes a Unicode string as UTF-8.
     *
     * @param s
     *            string to encode
     * @return Base64 string
     */
    public static String base64UrlEncode(final String s) {

        return base64urlEncode(s.getBytes(UTF8));
    }

    /**
     * Prevent instantiation of utility class.
     */
    private Encoding() {

    }
}
