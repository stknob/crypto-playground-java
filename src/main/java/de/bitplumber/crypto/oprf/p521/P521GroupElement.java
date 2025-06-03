package de.bitplumber.crypto.oprf.p521;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Bytes;

import de.bitplumber.crypto.oprf.FieldElement;
import de.bitplumber.crypto.oprf.GroupElement;

public class P521GroupElement implements GroupElement {
	private static final ECNamedCurveParameterSpec curveSpec;
	private static final ECCurve curve;
	private final ECPoint value;

	protected static final int HASH_OUTPUT_SIZE = 64;
	protected static final int HASH_BLOCK_SIZE = 128;

	public static final P521GroupElement BASEPOINT;
	public static final P521GroupElement IDENTITY;
	public static final BigInteger n;	// group order
	public static final BigInteger q;	// prime field order
	public static final ECFieldElement A;
	public static final ECFieldElement B;
	public static final ECFieldElement Z;
	public static final int SIZE = 67;

	static {
		curveSpec = ECNamedCurveTable.getParameterSpec("secp521r1");
		curve = curveSpec.getCurve();
		q = curve.getField().getCharacteristic();
		n = curve.getOrder();
		BASEPOINT = new P521GroupElement(curveSpec.getG());
		IDENTITY = new P521GroupElement(curve.getInfinity());
		Z = curve.fromBigInteger(BigInteger.valueOf(-4).mod(q));
		A = curve.getA();
		B = curve.getB();
	}

	private static final record SqrtRatioResult(boolean is_gx1_square, ECFieldElement y1) {}
	private static SqrtRatioResult sqrt_ratio(ECFieldElement u, ECFieldElement v) {
		if (curve.getOrder().mod(BigInteger.valueOf(4)).equals(BigInteger.valueOf(3))) {
			return sqrt_ratio_3mod4(u, v);
		} else {
			return sqrt_ratio_generic(u, v);
		}
	}

	/**
	 * TODO: Some way to actually implement this in constant time?
	 * @param a
	 * @param b
	 * @param cond
	 * @return
	 */
	private static ECFieldElement cmov(ECFieldElement a, ECFieldElement b, boolean cond) {
		return cond ? b : a;
	}

	/**
	 *
	 * @param u
	 * @param v
	 * @return
	 */
	private static SqrtRatioResult sqrt_ratio_generic(ECFieldElement u, ECFieldElement v) {
		var l = BigInteger.ZERO;
		for (var o = q.subtract(BigInteger.ONE); o.mod(BigInteger.TWO).equals(BigInteger.ZERO); o = o.divide(BigInteger.TWO))
			l = l.add(BigInteger.ONE);

		final var c1 = l;
		final var _2n_pow_c1_1 = BigInteger.TWO.shiftLeft(c1.subtract(BigInteger.TWO).intValue());
		final var _2n_pow_c1   = _2n_pow_c1_1.multiply(BigInteger.TWO);
		final var c2 = q.subtract(BigInteger.ONE).divide(_2n_pow_c1);
		final var c3 = c2.subtract(BigInteger.ONE).divide(BigInteger.TWO);
		final var c4 = _2n_pow_c1.subtract(BigInteger.ONE);
		final var c5 = _2n_pow_c1_1;
		final var c6 = curve.fromBigInteger(Z.toBigInteger().modPow(c2, q));
		final var c7 = curve.fromBigInteger(Z.toBigInteger().modPow(c2.add(BigInteger.ONE).divide(BigInteger.TWO), q));

		var tv1 = c6;
		var tv2 = curve.fromBigInteger(v.toBigInteger().modPow(c4, q));
		var tv3 = tv2.square().multiply(v);
		var tv5 = curve.fromBigInteger(tv3.multiply(u).toBigInteger().modPow(c3, q)).multiply(tv2);
		tv2 = tv5.multiply(v);
		tv3 = tv5.multiply(u);
		var tv4 = tv3.multiply(tv2);
		tv5 = curve.fromBigInteger(tv4.toBigInteger().modPow(c5, q));
		final var isQR = tv5.isOne();
		tv2 = tv3.multiply(c7);
		tv5 = tv4.multiply(tv1);
		tv3 = cmov(tv2, tv3, isQR);
		tv4 = cmov(tv5, tv4, isQR);

		for (var i = c1; i.compareTo(BigInteger.ONE) >= 1; i = i.subtract(BigInteger.ONE)) {
			var _tv5 = BigInteger.TWO.shiftLeft(i.subtract(BigInteger.valueOf(3)).intValue());
			var tvv5 = curve.fromBigInteger(tv4.toBigInteger().modPow(_tv5, q));
			final var e1 = tvv5.isOne();
			tv2 = tv3.multiply(tv1);
			tv1 = tv1.multiply(tv1);
			tvv5 = tv4.multiply(tv1);
			tv3 = cmov(tv2,  tv3, e1);
			tv4 = cmov(tvv5, tv4, e1);
		}
		return new SqrtRatioResult(isQR, tv3);
	}

	/**
	 *
	 * @param u
	 * @param v
	 * @return
	 */
	private static SqrtRatioResult sqrt_ratio_3mod4(ECFieldElement u, ECFieldElement v) {
		final var c1 = q.subtract(BigInteger.valueOf(3)).divide(BigInteger.valueOf(4));
		final var c2 = Z.negate().sqrt();

		var tv2 = u.multiply(v);
		var tv1 = v.square().multiply(tv2);
		var y1 = curve.fromBigInteger(tv1.toBigInteger().modPow(c1, q)).multiply(tv2);
		var y2 = y1.multiply(c2);
		var tv3 = y1.square().multiply(v);
		final var isQR = tv3.equals(u);
		var y = cmov(y2, y1, isQR);
		return new SqrtRatioResult(isQR, y);
	}

	private static int sgn0_m_eq_1(ECFieldElement x) {
		return x.toBigInteger().mod(BigInteger.TWO).intValue();
	}

	private static ECPoint map_to_curve_simple_swu(ECFieldElement u) {
		if (!curve.isValidFieldElement(Z.toBigInteger())) throw new IllegalStateException("Z not valid Fp");
		if (!curve.isValidFieldElement(A.toBigInteger())) throw new IllegalStateException("A not valid Fp");
		if (!curve.isValidFieldElement(B.toBigInteger())) throw new IllegalStateException("B not valid Fp");

		var tv1 = u.square().multiply(Z);
		var tv2 = tv1.square().add(tv1);
		var tv3 = tv2.addOne().multiply(B);
		var tv4 = cmov(Z, tv2.negate(), !tv2.isZero()).multiply(A);
		tv2 = tv3.square();
		var tv6 = tv4.square();
		var tv5 = tv6.multiply(A);
		tv2 = tv2.add(tv5).multiply(tv3);
		tv6 = tv6.multiply(tv4);
		tv5 = tv6.multiply(B);
		tv2 = tv2.add(tv5);

		final var sqr = sqrt_ratio(tv2, tv6);
		var x = tv1.multiply(tv3);
		var y = tv1.multiply(u).multiply(sqr.y1());
		x = cmov(x, tv3, sqr.is_gx1_square());
		y = cmov(y, sqr.y1(), sqr.is_gx1_square());

		final var e1 = sgn0_m_eq_1(u) == sgn0_m_eq_1(y);
		y = cmov(y.negate(), y, e1);
		x = x.multiply(tv4.invert());

		if (!curve.isValidFieldElement(x.toBigInteger())) throw new IllegalStateException("x not valid Fp");
		if (!curve.isValidFieldElement(y.toBigInteger())) throw new IllegalStateException("y not valid Fp");
		return curve.createPoint(x.toBigInteger(), y.toBigInteger());
	}

	private static ECPoint clear_cofactor(ECPoint p) {
		return p.multiply(curve.getCofactor());
	}

	protected static byte[] hash(byte[] input) {
		final var hash = new SHA512Digest();
		hash.update(input, 0, input.length);

		final var output = new byte[hash.getDigestSize()];
		hash.doFinal(output, 0);
		return output;
	}

	protected static byte[] I2OSP(long input, int size) {
		return BigIntegers.asUnsignedByteArray(size, BigInteger.valueOf(input));
	}

	protected static byte[] expand_message_xmd(byte[] msg, byte[] dst, int lengthInBytes) {
		if (dst.length > 255) {
			dst = hash(Arrays.concatenate("H2C-OVERSIZE-DST-".getBytes(StandardCharsets.UTF_8), dst));
		}

		final var ell = Math.ceilDiv(lengthInBytes, HASH_OUTPUT_SIZE);
		if (lengthInBytes > 65535 || ell > 255) throw new IllegalArgumentException("expand_message_xmd: Invalid lengthInBytes");

		final var dstPrime = Arrays.concatenate(dst, I2OSP(dst.length, 1));
		final var lengthInBytesStr = I2OSP(lengthInBytes, 2);
		final var zPad = I2OSP(0, HASH_BLOCK_SIZE);

		final var b = new byte[ell][];
		final var b0 = hash(Arrays.concatenate(new byte[][]{ zPad, msg, lengthInBytesStr, I2OSP(0, 1), dstPrime }));
		b[0] = hash(Arrays.concatenate(new byte[][]{ b0, I2OSP(1, 1), dstPrime }));

		if (ell > 1) {
			final var tmp = new byte[HASH_OUTPUT_SIZE];
			for (int i = 1; i < ell; i++) {
				Bytes.xor(b0.length, b0, b[i - 1], tmp);
				b[i] = hash(Arrays.concatenate(tmp, I2OSP(i + 1, 1), dstPrime));
			}
		}

		final var output = Arrays.concatenate(b);
		return Arrays.copyOfRange(output, 0, lengthInBytes);
	}

	private static ECFieldElement[][] hash_to_field(byte[] input, byte[] DST, int m, int k, int count) {
		final var L = Math.ceilDiv(curve.getFieldSize() + k, 8);
		final var lengthInBytes = count * m * L;
		final var uniformBytes = expand_message_xmd(input, DST, lengthInBytes);
		final var u = new ECFieldElement[count][];
		for (int i = 0; i < count; i++) {
			final var e = new ECFieldElement[m];
			for (int j = 0; j < m; j++) {
				final var elmOffset = L * (j + i * m);
				final var tv = Arrays.copyOfRange(uniformBytes, elmOffset, elmOffset + L);
				e[j] = curve.fromBigInteger(BigIntegers.fromUnsignedByteArray(tv).mod(q));
			}
			u[i] = e;
		}
		return u;
	}

	private static ECPoint hash_to_curve(byte[] input, byte[] DST) {
		final var u = hash_to_field(input, DST, 1, 256, 2);
		final var q0 = map_to_curve_simple_swu(u[0][0]);
		final var q1 = map_to_curve_simple_swu(u[1][0]);

		if (!q0.isValid()) throw new IllegalStateException("HtC q0 invalid");
		if (!q1.isValid()) throw new IllegalStateException("HtC q1 invalid");

		final var r = q0.add(q1);
		return clear_cofactor(r);
	}

	public P521GroupElement(ECPoint value) {
		this.value = value;
	}

	public static P521GroupElement fromBytes(byte[] input) throws Exception {
		return new P521GroupElement(curveSpec.getCurve().decodePoint(input));
	}

	public static P521GroupElement hashToGroup(byte[] input, byte[] DST) {
		final var p = hash_to_curve(input, DST);
		return new P521GroupElement(p);
	}

	public byte[] toByteArray() {
		return this.value.getEncoded(true);
	}

	public ECPoint value() {
		return this.value;
	}

	public P521GroupElement add(GroupElement other) {
		final var otherVal = ((P521GroupElement)other).value();
		return new P521GroupElement(this.value.add(otherVal));
	}

	public P521GroupElement subtract(GroupElement other) {
		final var otherVal = ((P521GroupElement)other).value();
		return new P521GroupElement(this.value.subtract(otherVal));
	}

	public P521GroupElement multiply(FieldElement scalar) {
		final var otherVal = ((P521FieldElement)scalar).value();
		return new P521GroupElement(this.value.multiply(otherVal.toBigInteger()));
	}

    public boolean equals(GroupElement other) {
		final var otherVal = ((P521GroupElement)other).value();
        return this.value.equals(otherVal);
    }

    public boolean ctEquals(GroupElement other) {
		final var otherVal = ((P521GroupElement)other).value();
        return this.value.equals(otherVal);
    }
}
