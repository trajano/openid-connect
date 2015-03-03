package net.trajano.openidconnect.crypto;

import java.math.BigInteger;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlEnumValue;

/**
 * http://csrc.nist.gov/groups/ST/toolkit/documents/dss/NISTReCur.pdf
 */
@XmlEnum
public enum NamedEllipticCurve {
    @XmlEnumValue("P-192")
    P192("6277101735386680763835789423207666416083908700390324961279", // p
            "6277101735386680763835789423176059013767194773182842284081", // r
            "3045ae6fc8422f64ed579528d38120eae12196d5", // s
            "3099d2bbbfcb2538542dcd5fb078b6ef5f3d6fe2c745de65", // c
            "64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", // b
            "188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012", // G_x
            "07192b95ffc8da78631011ed6b24cdd573f977a11e794811" // G_y
    ),

    @XmlEnumValue("P-224")
    P224("26959946667150639794667015087019630673557916260026308143510066298881", "26959946667150639794667015087019625940457807714424391721682722368061", "bd71344799d5c7fcdc45b59fa3b9ab8f6a948bc5", "5b056c7e11dd68f40469ee7f3c7a7d74f7d121116506d031218291fb", "b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4", "b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21", "bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34"),

    @XmlEnumValue("P-256")
    P256("115792089210356248762697446949407573530086143415290314195533631308867097853951", "115792089210356248762697446949407573529996955224135760342422259061068512044369", "c49d360886e704936a6678e1139d26b7819f7e90", "7efba1662985be9403cb055c75d4f7e0ce8d84a9c5114abcaf3177680104fa0d", "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),

    @XmlEnumValue("P-384")
    P384("39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319", "39402006196394479212279040100143613805079739270465446667946905279627659399113263569398956308152294913554433653942643", "a335926aa319a27a1d00896a6773a4827acdac73", "79d1e655f868f02fff48dcdee14151ddb80643c1406d0ca10dfe6fc52009540a495e8042ea5f744f6e184667cc722483", "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef", "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7", "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f"),

    @XmlEnumValue("P-521")
    P521("6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151", "6864797660130609714981900799081393217269435300143305409394463459185543183397655394245057746333217197532963996371363321113864768612440380340372808892707005449", "d09e8800291cb85396cc6717393284aaa0da64ba", "0b48bfa5f420a34949539d2bdfc264eeeeb077688e44fbf0ad8f6d0edb37bd6b533281000518e19f1b9ffbe0fe9ed8a3c2200b8f875e523868c70c1e5bf55bad637", "051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00", "c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66",
            "11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650");

    private final ECParameterSpec parameterSpec;

    /**
     * Builds the curve using the values from NIST.
     *
     * @param pS
     *            the p value as a string. This is the prime modulus.
     * @param rS
     *            the r value as a string. This is the prime order.
     * @param sS
     *            the s value as a string. This is a base-16 value. The 160-bit
     *            input seed s to the SHA-1 based algorithm
     * @param cS
     *            output of the SHA-1 based algorithm
     * @param bS
     *            coefficient
     * @param gxS
     *            The base point x coordinate G<sub>x</sub>
     * @param gyS
     *            The base point y coordinate G<sub>y</sub>
     */
    private NamedEllipticCurve(final String pS, final String rS, final String sS, final String cS, final String bS, final String gxS, final String gyS) {

        final BigInteger p = new BigInteger(pS);
        final BigInteger r = new BigInteger(rS);
        final BigInteger s = new BigInteger(sS, 16);

        final EllipticCurve curve = new EllipticCurve(new ECFieldFp(p), r, s);

        final BigInteger gx = new BigInteger(gxS, 16);
        final BigInteger gy = new BigInteger(gyS, 16);
        final ECPoint g = new ECPoint(gx, gy);

        final BigInteger b = new BigInteger(bS, 16);
        final BigInteger c = new BigInteger(cS, 16);
        assert validate(b, c, p);
        parameterSpec = new ECParameterSpec(curve, g, b, 1);

    }

    private static boolean validate(BigInteger b,
            BigInteger c,
            BigInteger p) {

        return ((b.pow(2)).multiply(c)
                .add(new BigInteger("27")).mod(p)).equals(BigInteger.ZERO);
    }

    public ECParameterSpec toECParameterSpec() {

        return parameterSpec;
    }
}
