package de.bitplumber.crypto.htc;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

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

public class ECCurveHtCHasher {
    private final ECNamedCurveParameterSpec curveSpec;
    private final ECCurve curve;
	private final ECCurve isogenyCurve;
	private final ECFieldElement A;  //NOSONAR
	private final ECFieldElement B;  //NOSONAR
	private final ECFieldElement Z;  //NOSONAR
	private final BigInteger q;
	private final BigInteger G; //NOSONAR
	// private final BigInteger H; //NOSONAR

	protected final byte[] hashToCurveDST;
	protected final byte[] encodeToCurveDST;
	protected final ExtendedDigest hash;
	protected final int hashOutputSize;
	protected final int hashBlockSize;
	protected final int m;
	protected final int k;

	protected ECCurveHtCHasher(final String curveName, final ExtendedDigest hash, final String hashToCurveDST, final String encodeToCurveDST, final ECCurve isogenyCurve, final int Z, final int m, final int k) {
		// Curve and parameters
		this.curveSpec = ECNamedCurveTable.getParameterSpec(curveName);
		this.curve = curveSpec.getCurve();
		this.isogenyCurve = isogenyCurve;				// Optional: isogeny curve parameters

		// Either use isogeny curve parameters for operations or main curve
		final var htcCurve = ObjectUtils.defaultIfNull(isogenyCurve, curve);
		this.q = htcCurve.getField().getCharacteristic();	// Field modulus
		this.Z = htcCurve.fromBigInteger(BigInteger.valueOf(Z).mod(q));
		// this.H = htcCurve.getCofactor();
		this.G = htcCurve.getOrder();						// Curve order
		this.A = htcCurve.getA();
		this.B = htcCurve.getB();

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

	protected ECCurveHtCHasher(final String curveName, final ExtendedDigest hash, final String hashToCurveDST, final String encodeToCurveDST, final int Z, final int m, final int k) {
		this(curveName, hash, hashToCurveDST, encodeToCurveDST, null, Z, m, k);
	}


	/**
	 * Create a hasher instance for the P256-SHA256 suite
	 * @return
	 */
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

	/**
	 * Create a hasher instance for the P384-SHA384 suite
	 * @return
	 */
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

	/**
	 * Create a hasher instance for the P521-SHA512 suite
	 * @return
	 */
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

	/**
	 * Create a hasher instance for the secp256k1-SHA256 suite
	 * Missing secp256k1 isogeny parameters taken from https://github.com/armfazh/hash-to-curve-ref/
	 * @return
	 */
	public static ECCurveHtCHasher createSecp256k1() {
		final var isogenyCurve = new ECCurve.Fp(
			new BigInteger("00fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16),
			new BigInteger("003f8731abdd661adca08a5558f0f5d272e953d363cb6f0e5d405447c01a444533", 16),
			BigInteger.valueOf(1771),
			new BigInteger("00fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16),
			BigInteger.valueOf(1)
		);

		return new ECCurveHtCHasher(
			"secp256k1",
			new SHA256Digest(),
			"secp256k1_XMD:SHA-256_SSWU_RO_",
			"secp256k1_XMD:SHA-256_SSWU_NU_",
			isogenyCurve,
			-11,
			1,
			128
		);
	}


	/**
	 * @return
	 */
	public String getCurveName() {
		return curveSpec.getName();
	}

	/**
	 * @return
	 */
	public ECNamedCurveParameterSpec getCurveSpec() {
		return curveSpec;
	}

	/**
	 * @return
	 */
	public ECCurve getCurve() {
		return curve;
	}

	/**
	 * @return
	 */
	public String getHashName() {
		return this.hash.getAlgorithmName();
	}

	/**
	 * @return
	 */
	public int getHashOutputSize() {
		return this.hashOutputSize;
	}

	/**
	 * @return
	 */
	public int getHashBlockSize() {
		return this.hashBlockSize;
	}

	/**
	 * Get the curve security level 'k'
	 * @return
	 */
	public int getSecurityLevel() {
		return this.k;
	}

	protected static final record SqrtRatioResult(boolean is_gx1_square, ECFieldElement y1) {}
	protected SqrtRatioResult sqrtRatio(ECCurve curve, ECFieldElement u, ECFieldElement v) {
		if (G.mod(BigInteger.valueOf(4)).equals(BigInteger.valueOf(3))) {
			return sqrtRatio3Mod4(curve, u, v);
		} else {
			return sqrtRatioGeneric(curve, u, v);
		}
	}

	/**
	 * TODO: Some way to actually implement this in constant time?
	 * @param a
	 * @param b
	 * @param cond
	 * @return
	 */
	protected ECFieldElement cmov(ECFieldElement a, ECFieldElement b, boolean cond) {
		return cond ? b : a;
	}

	/**
	 * Port of noble-curves' SWUFpSqrtRatio() generic sqrt_ratio TypeScript implementation
	 *    noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com)
	 * @param u
	 * @param v
	 * @return
	 */
	protected SqrtRatioResult sqrtRatioGeneric(ECCurve curve, ECFieldElement u, ECFieldElement v) {
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
	protected SqrtRatioResult sqrtRatio3Mod4(ECCurve curve, ECFieldElement u, ECFieldElement v) {
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

	protected int sgn0_m_eq_1(ECFieldElement x) {
		return x.toBigInteger().mod(BigInteger.TWO).intValue();
	}

	private static final BigInteger[] secp256k1_xnum = new BigInteger[]{
		new BigInteger("8e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38daaaaa8c7", 16),
		new BigInteger("07d3d4c80bc321d5b9f315cea7fd44c5d595d2fc0bf63b92dfff1044f17c6581", 16),
		new BigInteger("534c328d23f234e6e2a413deca25caece4506144037c40314ecbd0b53d9dd262", 16),
		new BigInteger("8e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38daaaaa88c", 16),
	};

	private static final BigInteger[] secp256k1_xden = new BigInteger[]{
		new BigInteger("d35771193d94918a9ca34ccbb7b640dd86cd409542f8487d9fe6b745781eb49b", 16),
		new BigInteger("edadc6f64383dc1df7c4b2d51b54225406d36b641f5e41bbc52a56612a8c6d14", 16),
	};

	private static final BigInteger[] secp256k1_ynum = new BigInteger[]{
		new BigInteger("4bda12f684bda12f684bda12f684bda12f684bda12f684bda12f684b8e38e23c", 16),
		new BigInteger("c75e0c32d5cb7c0fa9d0a54b12a0a6d5647ab046d686da6fdffc90fc201d71a3", 16),
		new BigInteger("29a6194691f91a73715209ef6512e576722830a201be2018a765e85a9ecee931", 16),
		new BigInteger("2f684bda12f684bda12f684bda12f684bda12f684bda12f684bda12f38e38d84", 16),
	};

	private static final BigInteger[] secp256k1_yden = new BigInteger[]{
		new BigInteger("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffff93b", 16),
		new BigInteger("7a06534bb8bdb49fd5e9e6632722c2989467c1bfc8e8d978dfb425d2685c2573", 16),
		new BigInteger("6484aa716545ca2cf3a70c3fa8fe337e0a3d21162f0d6299a7bf8192bfd2a76f", 16),
	};

	/**
	 * RFC 9830 - E.1. 3-Isogeny Map for secp256k1
	 * @param input A point on the secp256k1 isogeny curve E'
	 * @return A point on the secp256k1 curve E
	 */
	protected ECPoint isoMap3(ECPoint input) {
		final var xIn = input.getAffineXCoord();
		final var yIn = input.getAffineYCoord();

		// x = x_num / x_den
		var xNum = isogenyCurve.fromBigInteger(secp256k1_xnum[3]);
		xNum = xIn.multiply(xNum).add(isogenyCurve.fromBigInteger(secp256k1_xnum[2]));
		xNum = xIn.multiply(xNum).add(isogenyCurve.fromBigInteger(secp256k1_xnum[1]));
		xNum = xIn.multiply(xNum).add(isogenyCurve.fromBigInteger(secp256k1_xnum[0]));

		var xDen = xIn.add(isogenyCurve.fromBigInteger(secp256k1_xden[1]));
		xDen = xIn.multiply(xDen).add(isogenyCurve.fromBigInteger(secp256k1_xden[0]));

		// y = y' * x_num / x_den
		var yNum = isogenyCurve.fromBigInteger(secp256k1_ynum[3]);
		yNum = xIn.multiply(yNum).add(isogenyCurve.fromBigInteger(secp256k1_ynum[2]));
		yNum = xIn.multiply(yNum).add(isogenyCurve.fromBigInteger(secp256k1_ynum[1]));
		yNum = xIn.multiply(yNum).add(isogenyCurve.fromBigInteger(secp256k1_ynum[0]));

		var yDen = xIn.add(isogenyCurve.fromBigInteger(secp256k1_yden[2]));
		yDen = xIn.multiply(yDen).add(isogenyCurve.fromBigInteger(secp256k1_yden[1]));
		yDen = xIn.multiply(yDen).add(isogenyCurve.fromBigInteger(secp256k1_yden[0]));

		final var x = xNum.divide(xDen).toBigInteger();
		final var y = yNum.divide(yDen).multiply(yIn).toBigInteger();
		return curve.createPoint(x, y);
	}

	protected ECPoint mapToCurveSimpleSWU(ECCurve curve, ECFieldElement u) {
		if (!curve.isValidFieldElement(u.toBigInteger()))
			throw new IllegalStateException("u not valid Fp");

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

		final var sqr = sqrtRatio(curve, tv2, tv6);
		var x = tv1.multiply(tv3);
		var y = tv1.multiply(u).multiply(sqr.y1());
		x = cmov(x, tv3, sqr.is_gx1_square());
		y = cmov(y, sqr.y1(), sqr.is_gx1_square());

		final var e1 = sgn0_m_eq_1(u) == sgn0_m_eq_1(y);
		y = cmov(y.negate(), y, e1);
		x = x.divide(tv4);
		return curve.createPoint(x.toBigInteger(), y.toBigInteger());
	}

	protected ECPoint clearCofactor(ECCurve curve, ECPoint p) {
		return p.multiply(curve.getCofactor());
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
	protected ECFieldElement[][] hashToField(ECCurve curve, byte[] input, byte[] DST, int m, int k, int count) {
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
	protected ECFieldElement[][] hashToField(byte[] input, byte[] DST, int count) {
		switch (curveSpec.getName()) {
		case "secp256k1":
			throw new UnsupportedOperationException("Operation not supported for secp256k1");
		default:
			return hashToField(curve, input, DST, m, k, count);
		}
	}

	/**
	 * Hash input to a point on the hasher's curve
	 * @param input The message to map onto the curve
	 * @param DST Optional: custom domain separation tag (DST)
	 * @return
	 */
	public ECPoint hashToCurve(byte[] input, byte[] DST) {
		final var htcDST = ObjectUtils.defaultIfNull(DST, hashToCurveDST);

		final ECPoint q0, q1;
		switch (curveSpec.getName()) {
		case "secp256k1": {
			// AB == 0 special case for secp256k1
			final var u = hashToField(isogenyCurve, input, htcDST, m, k, 2);
			q0 = isoMap3(mapToCurveSimpleSWU(isogenyCurve, u[0][0]));
			q1 = isoMap3(mapToCurveSimpleSWU(isogenyCurve, u[1][0]));
			break;
		}
		default: {
			final var u = hashToField(curve, input, htcDST, m, k, 2);
			q0 = mapToCurveSimpleSWU(curve, u[0][0]);
			q1 = mapToCurveSimpleSWU(curve, u[1][0]);
			break;
		}}

		final var r = q0.add(q1);
		if (!r.isValid()) throw new IllegalStateException("HashToCurve R invalid");
		return clearCofactor(curve, r);
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
		final var etcDST = ObjectUtils.defaultIfNull(DST, encodeToCurveDST);

		final ECPoint q;
		switch (curveSpec.getName()) {
		case "secp256k1": {
			final var u = hashToField(isogenyCurve, input, etcDST, m, k, 1);
			q = isoMap3(mapToCurveSimpleSWU(isogenyCurve, u[0][0]));
			break;
		}
		default: {
			final var u = hashToField(curve, input, etcDST, m, k, 1);
			q = mapToCurveSimpleSWU(curve, u[0][0]);
			break;
		}}

		if (!q.isValid()) throw new IllegalStateException("EncodeToCurve Q invalid");
		return clearCofactor(curve, q);
	}
}
