package de.bitplumber.crypto.oprf;

import java.math.BigInteger;
import java.util.Objects;

import org.apache.commons.lang3.RandomUtils;
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

import de.bitplumber.crypto.h2c.ECCurveHasher;

class ECCurveSuite {
	private static final byte[] EMPTY_ARRAY = new byte[]{};

	private final ECNamedCurveParameterSpec curveSpec;
	private final ECCurve curve;
	private final int k;

	private final String name;

	private final ECCurveHasher h2c;
	private final ExtendedDigest hash;
	private final int elementSize;
	private final int scalarSize;

	private ECCurveSuite(final String name, final String curveName, final ExtendedDigest hash, final ECCurveHasher h2c, final int k) {
		this.curveSpec = ECNamedCurveTable.getParameterSpec(curveName);
		this.curve = curveSpec.getCurve();
		this.name = name;
		this.hash = hash;
		this.h2c = h2c;
		this.k = k;

		this.elementSize = curve.getAffinePointEncodingLength(true);
		this.scalarSize  = curve.getFieldElementEncodingLength();
	}

	public String getName() {
		return this.name;
	}

	public String getCurveName() {
		return this.curveSpec.getName();
	}

	public ECCurve getCurve() {
		return this.curve;
	}

	public int getScalarSize() {
		return this.scalarSize;
	}

	public int getElementSize() {
		return this.elementSize;
	}

	public ECPoint getG() {
		return this.curveSpec.getG();
	}

	public static ECCurveSuite createP256() {
		return new ECCurveSuite(
			"P256-SHA256",
			"secp256r1",
			new SHA256Digest(),
			ECCurveHasher.createP256(),
			128);
	}

	public static ECCurveSuite createP384() {
		return new ECCurveSuite(
			"P384-SHA384",
			"secp384r1",
			new SHA384Digest(),
			ECCurveHasher.createP384(),
			192);
	}

	public static ECCurveSuite createP521() {
		return new ECCurveSuite(
			"P521-SHA512",
			"secp521r1",
			new SHA512Digest(),
			ECCurveHasher.createP521(),
			256);
	}

	protected byte[] I2OSP(long input, int size) {
		return BigIntegers.asUnsignedByteArray(size, BigInteger.valueOf(input));
	}

	public byte[] encodeScalar(ECFieldElement scalar) {
		final var encoded = scalar.getEncoded();
		if (encoded == null || encoded.length != scalarSize) {
			throw new IllegalArgumentException(String.format("Invalid scalar encoding size: '%d' vs '%d' expected",
				Objects.requireNonNullElse(encoded, EMPTY_ARRAY).length, scalarSize));
		}
		return encoded;
	}

	public ECFieldElement decodeScalar(byte[] encoded) {
		final var s = BigIntegers.fromUnsignedByteArray(encoded);
		if (!curve.isValidFieldElement(s)) {
			throw new IllegalArgumentException(String.format("Encoded %s scalar is invalid",
				curveSpec.getName()));
		}
		return curve.fromBigInteger(s);
	}

	public ECFieldElement invertScalar(ECFieldElement scalar) {
        return curve.fromBigInteger(scalar.toBigInteger().modInverse(curve.getOrder()));
	}

	public byte[] encodeElement(ECPoint element) {
		final var encoded = element.getEncoded(true);
		if (encoded == null || encoded.length != elementSize) {
			throw new IllegalArgumentException(String.format("Invalid element encoding size: '%d' vs '%d' expected",
				Objects.requireNonNullElse(encoded, EMPTY_ARRAY).length, elementSize));
		}
		return encoded;
	}

	public ECPoint decodeElement(byte[] encoded) {
		final var p = curve.decodePoint(encoded);
		if (p == null || !p.isValid()) {
			throw new IllegalArgumentException(String.format("Encoded %s point is invalid",
				curveSpec.getName()));
		}
		return p;
	}

	private ECFieldElement scalarFromBytesModOrderWide(byte[] uniformBytes) {
        final var s = BigIntegers.fromUnsignedByteArray(uniformBytes).mod(curve.getOrder());
        if (!curve.isValidFieldElement(s)) {
			throw new IllegalArgumentException("Invalid field element");
		}
		return curve.fromBigInteger(s);
	}

	public ECFieldElement randomScalar() {
		final var ell = Math.ceilDiv(curve.getFieldSize() + k, 8);
		final var uniformBytes = RandomUtils.secureStrong().randomBytes(ell);
		return scalarFromBytesModOrderWide(uniformBytes);
	}

	protected ECPoint hashToGroup(byte[] msg, byte[] customDST, byte[] context) {
		final var dst = Objects.requireNonNullElseGet(customDST, () -> Arrays.concatenate(Labels.HASH_TO_GROUP, context));
		return h2c.hashToCurve(msg, dst);
	}

	protected ECFieldElement hashToScalar(byte[] msg, byte[] customDST, byte[] context) {
		final var ell = Math.ceilDiv(curve.getFieldSize() + k, 8);
		final var dst = Objects.requireNonNullElseGet(customDST, () -> Arrays.concatenate(Labels.HASH_TO_SCALAR, context));
		final var s = h2c.expandMessage(msg, dst, ell);
		return scalarFromBytesModOrderWide(s);
	}

	public KeyPair randomKeyPair() {
		final var secretScalar  = randomScalar();
		final var publicElement = curveSpec.getG().multiply(secretScalar.toBigInteger());
		return new KeyPair(encodeScalar(secretScalar), encodeElement(publicElement));
	}

	public KeyPair deriveKeyPair(byte[] seed, byte[] info, byte[] context) throws Exception {
		final var nullSafeInfo = Objects.requireNonNullElse(info, EMPTY_ARRAY);
		final var deriveInput = Arrays.concatenate(seed, I2OSP(nullSafeInfo.length, 2), nullSafeInfo);
		final var deriveDST = Arrays.concatenate(Labels.DERIVE_KEYPAIR, context);

		int counter = 0;
		ECFieldElement secretScalar = curve.fromBigInteger(BigInteger.ZERO);
		while (secretScalar.isZero()) {
			if (counter > 255) throw new Exception("Failed to derive secret key");
			secretScalar = hashToScalar(Arrays.concatenate(deriveInput, I2OSP(counter, 1)), deriveDST, context);
			counter++;
		}

		final var publicElement = curveSpec.getG().multiply(secretScalar.toBigInteger());
		return new KeyPair(encodeScalar(secretScalar), encodeElement(publicElement));
	}

	public static final record Proof(byte[] c, byte[] s){
		public static Proof fromBytes(ECCurveSuite suite, byte[] input) {
			final var scalarSize = suite.getScalarSize();
			final var c = Arrays.copyOfRange(input, 0, scalarSize);
			final var s = Arrays.copyOfRange(input, scalarSize, input.length);
			return new Proof(c, s);
		}

		public byte[] toByteArray() {
			return Arrays.concatenate(c, s);
		}
	}

	protected byte[] hash(byte[] input) {
		final var output = new byte[hash.getDigestSize()];
		hash.reset();
		hash.update(input, 0, input.length);
		hash.doFinal(output, 0);
		return output;
	}

	protected static final record CompositesResult(ECPoint M, ECPoint Z) {}

	protected CompositesResult computeCompositesFast(ECFieldElement k, ECPoint B, ECPoint[] C, ECPoint[] D, byte[] context) {
		final var bm = encodeElement(B);
		final var seedDST = Arrays.concatenate(Labels.SEED_DST_PREFIX, context);
		final var seed = hash(Arrays.concatenate(
			I2OSP(bm.length, 2), bm,
			I2OSP(seedDST.length, 2), seedDST));

		var M = curve.getInfinity();
		for (var i = 0; i < C.length; i++) {
			final var Ci = encodeElement(C[i]);
			final var Di = encodeElement(D[i]);
			final var di = hashToScalar(Arrays.concatenate(new byte[][]{
				I2OSP(seed.length, 2), seed,
				I2OSP(i, 2),
				I2OSP(Ci.length, 2), Ci,
				I2OSP(Di.length, 2), Di,
				Labels.COMPOSITE
			}), null, context);

			M = C[i].multiply(di.toBigInteger()).add(M);
		}

		final var Z = M.multiply(k.toBigInteger());

		return new CompositesResult(M, Z);
	}

	protected CompositesResult computeComposites(ECPoint B, ECPoint[] C, ECPoint[] D, byte[] context) {
		final var bm = encodeElement(B);
		final var seedDST = Arrays.concatenate(Labels.SEED_DST_PREFIX, context);
		final var seed = hash(Arrays.concatenate(
			I2OSP(bm.length, 2), bm,
			I2OSP(seedDST.length, 2), seedDST));

		var M = curve.getInfinity();
		var Z = curve.getInfinity();
		for (var i = 0; i < C.length; i++) {
			final var Ci = encodeElement(C[i]);
			final var Di = encodeElement(D[i]);
			final var di = hashToScalar(Arrays.concatenate(new byte[][]{
				I2OSP(seed.length, 2), seed,
				I2OSP(i, 2),
				I2OSP(Ci.length, 2), Ci,
				I2OSP(Di.length, 2), Di,
				Labels.COMPOSITE
			}), null, context);

			M = C[i].multiply(di.toBigInteger()).add(M);
			Z = D[i].multiply(di.toBigInteger()).add(Z);
		}

		return new CompositesResult(M, Z);
	}

	/**
	 * Perform generateProof scalar operations mod G
	 * @param k
	 * @param c
	 * @param r
	 * @return
	 */
	protected ECFieldElement generateS(ECFieldElement k, ECFieldElement c, ECFieldElement r) {
		final var kb = k.toBigInteger();
		final var cb = c.toBigInteger();
		final var rb = r.toBigInteger();
		return curve.fromBigInteger(rb.subtract(cb.multiply(kb)).mod(curve.getOrder()));
	}

	protected Proof generateProof(ECFieldElement k, ECPoint A, ECPoint B, ECPoint[] C, ECPoint[] D, ECFieldElement proofRandomScalar, byte[] context) {
		final var MZ = computeCompositesFast(k, B, C, D, context);
		final var M = MZ.M();
		final var Z = MZ.Z();

		final var r = Objects.requireNonNullElseGet(proofRandomScalar, () -> randomScalar());
		final var t2 = A.multiply(r.toBigInteger());
		final var t3 = M.multiply(r.toBigInteger());

		final var bm = encodeElement(B);
		final var a0 = encodeElement(M);
		final var a1 = encodeElement(Z);
		final var a2 = encodeElement(t2);
		final var a3 = encodeElement(t3);

		final var challengeTranscript = Arrays.concatenate(new byte[][]{
			I2OSP(bm.length, 2), bm,
			I2OSP(a0.length, 2), a0,
			I2OSP(a1.length, 2), a1,
			I2OSP(a2.length, 2), a2,
			I2OSP(a3.length, 2), a3,
			Labels.CHALLENGE
		});

		final var c = hashToScalar(challengeTranscript, null, context);
		final var s = generateS(k, c, r);
		return new Proof(encodeScalar(c), encodeScalar(s));
	}

	protected Proof generateProof(ECFieldElement k, ECPoint A, ECPoint B, ECPoint[] C, ECPoint[] D, byte[] context) {
		return generateProof(k, A, B, C, D, null, context);
	}

	protected boolean verifyProof(ECPoint A, ECPoint B, ECPoint[] C, ECPoint[] D, Proof proof, byte[] context) throws Exception {
		final var MZ = computeComposites(B, C, D, context);
		final var M = MZ.M();
		final var Z = MZ.Z();
		final var c = decodeScalar(proof.c());
		final var s = decodeScalar(proof.s());

		final var t2 = A.multiply(s.toBigInteger()).add(B.multiply(c.toBigInteger()));
		final var t3 = M.multiply(s.toBigInteger()).add(Z.multiply(c.toBigInteger()));

		final var bm = encodeElement(B);
		final var a0 = encodeElement(M);
		final var a1 = encodeElement(Z);
		final var a2 = encodeElement(t2);
		final var a3 = encodeElement(t3);

		final var challengeTranscript = Arrays.concatenate(new byte[][]{
			I2OSP(bm.length, 2), bm,
			I2OSP(a0.length, 2), a0,
			I2OSP(a1.length, 2), a1,
			I2OSP(a2.length, 2), a2,
			I2OSP(a3.length, 2), a3,
			Labels.CHALLENGE
		});

		final var expectedC = hashToScalar(challengeTranscript, null, context);
		return expectedC.equals(c);
	}
}
