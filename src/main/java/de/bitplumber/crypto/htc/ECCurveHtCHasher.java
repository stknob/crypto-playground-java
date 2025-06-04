package de.bitplumber.crypto.htc;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.ObjectUtils;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Bytes;
import org.bouncycastle.util.encoders.Hex;

public class ECCurveHtCHasher {
    private final ECNamedCurveParameterSpec curveSpec;
    private final ECCurve curve;
	private final ECFieldElement A;  //NOSONAR
	private final ECFieldElement B;  //NOSONAR
	private final ECFieldElement Z;  //NOSONAR
	private final BigInteger q;
	private final BigInteger G; //NOSONAR
	private final BigInteger H; //NOSONAR

	protected final byte[] hashToCurveDST;
	protected final byte[] encodeToCurveDST;
	protected final ExtendedDigest hash;
	protected final int hashOutputSize;
	protected final int hashBlockSize;
	protected final int m;
	protected final int k;

	public ECCurveHtCHasher(final String curveName, final ExtendedDigest hash, final String hashToCurveDST, final String encodeToCurveDST, final int Z, final int m, final int k) {
		// Curve and parameters
		this.curveSpec = ECNamedCurveTable.getParameterSpec(curveName);
		this.curve = curveSpec.getCurve();
		this.q = curve.getField().getCharacteristic();	// Field modulus
		this.G = curve.getOrder();						// Curve order

		this.Z = curve.fromBigInteger(BigInteger.valueOf(Z).mod(q));
		this.H = curve.getCofactor();
		this.A = curve.getA();
		this.B = curve.getB();

		this.m = m;		// Same as curve.getField().getDimenstions() ??
		this.k = k;		// Security level in bits

		// Hash and parameters
		this.hash = hash;
		this.hashOutputSize = hash.getDigestSize();
		this.hashBlockSize = hash.getByteLength();

		// Misc parameters
		this.hashToCurveDST = hashToCurveDST.getBytes(StandardCharsets.UTF_8);
		this.encodeToCurveDST = encodeToCurveDST.getBytes(StandardCharsets.UTF_8);
	}

	public static ECCurveHtCHasher createP256() {
		return new ECCurveHtCHasher(
			"secp256r1",
			new SHA256Digest(),
			"P256_XMD:SHA-256_SSWU_RO_",
			"P256_XMD:SHA-256_SSWU_NU_",
			-10,
			1,
			128
		);
	}

	public static ECCurveHtCHasher createP384() {
		return new ECCurveHtCHasher(
			"secp384r1",
			new SHA384Digest(),
			"P384_XMD:SHA-384_SSWU_RO_",
			"P384_XMD:SHA-384_SSWU_NU_",
			-12,
			1,
			192
		);
	}

	public static ECCurveHtCHasher createP521() {
		return new ECCurveHtCHasher(
			"secp521r1",
			new SHA512Digest(),
			"P521_XMD:SHA-512_SSWU_RO_",
			"P521_XMD:SHA-512_SSWU_NU_",
			-4,
			1,
			256
		);
	}

	public String curveName() {
		return curveSpec.getName();
	}


	private static final record SqrtRatioResult(boolean is_gx1_square, ECFieldElement y1) {}
	private SqrtRatioResult sqrtRatio(ECFieldElement u, ECFieldElement v) {
		if (G.mod(BigInteger.valueOf(4)).equals(BigInteger.valueOf(3))) {
			return sqrtRatio3mod4(u, v);
		} else {
			return sqrtRatioGeneric(u, v);
		}
	}

	/**
	 * TODO: Some way to actually implement this in constant time?
	 * @param a
	 * @param b
	 * @param cond
	 * @return
	 */
	private ECFieldElement cmov(ECFieldElement a, ECFieldElement b, boolean cond) {
		return cond ? b : a;
	}

	/**
	 *
	 * @param u
	 * @param v
	 * @return
	 */
	private SqrtRatioResult sqrtRatioGeneric(ECFieldElement u, ECFieldElement v) {
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
	private SqrtRatioResult sqrtRatio3mod4(ECFieldElement u, ECFieldElement v) {
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

	private int sgn0_m_eq_1(ECFieldElement x) {
		return x.toBigInteger().mod(BigInteger.TWO).intValue();
	}

	private ECPoint map_to_curve_simple_swu(ECFieldElement u) {
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

		final var sqr = sqrtRatio(tv2, tv6);
		var x = tv1.multiply(tv3);
		var y = tv1.multiply(u).multiply(sqr.y1());
		x = cmov(x, tv3, sqr.is_gx1_square());
		y = cmov(y, sqr.y1(), sqr.is_gx1_square());

		final var e1 = sgn0_m_eq_1(u) == sgn0_m_eq_1(y);
		y = cmov(y.negate(), y, e1);
		x = x.divide(tv4);

		if (!curve.isValidFieldElement(x.toBigInteger())) throw new IllegalStateException("x not valid Fp");
		if (!curve.isValidFieldElement(y.toBigInteger())) throw new IllegalStateException("y not valid Fp");
		return curve.createPoint(x.toBigInteger(), y.toBigInteger());
	}

	private ECPoint clearCofactor(ECPoint p) {
		return p.multiply(H);
	}

	protected byte[] digest(byte[] input) {
		final var output = new byte[hashOutputSize];
		hash.reset();
		hash.update(input, 0, input.length);
		hash.doFinal(output, 0);
		return output;
	}

	protected byte[] I2OSP(long input, int size) {
		return BigIntegers.asUnsignedByteArray(size, BigInteger.valueOf(input));
	}

	protected byte[] expandMessageXMD(byte[] msg, byte[] dst, int lengthInBytes) {
		if (dst.length > 255) {
			dst = digest(Arrays.concatenate("H2C-OVERSIZE-DST-".getBytes(StandardCharsets.UTF_8), dst));
		}

		final var ell = Math.ceilDiv(lengthInBytes, hashOutputSize);
		if (lengthInBytes > 65535 || ell > 255) throw new IllegalArgumentException("expand_message_xmd: Invalid lengthInBytes");

		final var dstPrime = Arrays.concatenate(dst, I2OSP(dst.length, 1));
		final var lengthInBytesStr = I2OSP(lengthInBytes, 2);
		final var zPad = I2OSP(0, hashBlockSize);

		final var b = new byte[ell][];
		final var b0 = digest(Arrays.concatenate(new byte[][]{ zPad, msg, lengthInBytesStr, I2OSP(0, 1), dstPrime }));
		b[0] = digest(Arrays.concatenate(new byte[][]{ b0, I2OSP(1, 1), dstPrime }));

		if (ell > 1) {
			final var tmp = new byte[hashOutputSize];
			for (int i = 1; i < ell; i++) {
				Bytes.xor(b0.length, b0, b[i - 1], tmp);
				b[i] = digest(Arrays.concatenate(tmp, I2OSP(i + 1, 1), dstPrime));
			}
		}

		final var output = Arrays.concatenate(b);
		return Arrays.copyOfRange(output, 0, lengthInBytes);
	}

	/**
	 *
	 * @param input
	 * @param DST
	 * @param m
	 * @param k
	 * @param count
	 * @return
	 */
	protected ECFieldElement[][] hashToField(byte[] input, byte[] DST, int m, int k, int count) {
		final var L = Math.ceilDiv(curve.getFieldSize() + k, 8);
		final var lengthInBytes = count * m * L;
		final var uniformBytes = expandMessageXMD(input, DST, lengthInBytes);
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

	/**
	 *
	 * @param input
	 * @param DST
	 * @param m
	 * @param k
	 * @param count
	 * @return
	 */
	public ECFieldElement[][] hashToField(byte[] input, byte[] DST, int count) {
		return hashToField(input, DST, m, k, count);
	}

	/**
	 * Hash input to a point on the hasher's curve
	 * @param input The message to map onto the curve
	 * @param DST Optional: custom domain separation tag (DST)
	 * @return
	 */
	public ECPoint hashToCurve(byte[] input, byte[] DST) {
		final var htcDST = ObjectUtils.defaultIfNull(DST, hashToCurveDST);
		final var u  = hashToField(input, htcDST, m, k, 2);
		final var Q0 = map_to_curve_simple_swu(u[0][0]);
		final var Q1 = map_to_curve_simple_swu(u[1][0]);

		if (!Q0.isValid()) throw new IllegalStateException("HtC q0 invalid");
		if (!Q1.isValid()) throw new IllegalStateException("HtC q1 invalid");

		final var R = Q0.add(Q1);
		return clearCofactor(R);
	}

	public ECPoint hashToCurve(byte[] input) {
		return hashToCurve(input, null);
	}

	/**
	 * Hash input to a point on the hasher's curve
	 * @param input The message to map onto the curve
	 * @param DST Optional: custom domain separation tag (DST)
	 * @return
	 */
	public ECPoint encodeToCurve(byte[] input, byte[] DST) {
		final var htcDST = ObjectUtils.defaultIfNull(DST, encodeToCurveDST);
		final var u  = hashToField(input, htcDST, m, k, 1);
		final var Q = map_to_curve_simple_swu(u[0][0]);
		if (!Q.isValid()) throw new IllegalStateException("EncodeToCurve q invalid");
		return clearCofactor(Q);
	}
}
