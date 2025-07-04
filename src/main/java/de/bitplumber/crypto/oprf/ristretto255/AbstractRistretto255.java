package de.bitplumber.crypto.oprf.ristretto255;

import java.math.BigInteger;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.ObjectUtils;
import org.apache.commons.lang3.RandomUtils;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

import com.weavechain.curve25519.CompressedRistretto;
import com.weavechain.curve25519.RistrettoElement;
import com.weavechain.curve25519.Scalar;

import de.bitplumber.crypto.h2c.ExpandMessage;
import de.bitplumber.crypto.oprf.KeyPair;
import de.bitplumber.crypto.oprf.Labels;

public abstract class AbstractRistretto255 {
	public static final String SUITE_ID = "ristretto255-SHA512";
	protected static final int HASH_OUTPUT_SIZE = 64;
	protected static final int HASH_BLOCK_SIZE = 128;
	public static final int ELEMENT_SIZE = 32;
	public static final int SCALAR_SIZE = 32;

	protected abstract byte[] context();

	public byte[] encodeElement(RistrettoElement element) {
		return element.compress().toByteArray();
	}

	public RistrettoElement decodeElement(byte[] input) throws Exception {
		return new CompressedRistretto(input).decompress();
	}

	public byte[] encodeScalar(Scalar scalar) {
		return scalar.toByteArray();
	}

	public Scalar decodeScalar(byte[] input) throws Exception {
		return Scalar.fromCanonicalBytes(input);
	}

	protected RistrettoElement hashToGroup(byte[] hash, byte[] customDST) {
		final var dst = ObjectUtils.defaultIfNull(customDST, Arrays.concatenate(Labels.HASH_TO_GROUP, context()));
		final var uniformBytes = ExpandMessage.expandMessageXMD(new SHA512Digest(), hash, dst, HASH_OUTPUT_SIZE);
		return RistrettoElement.fromUniformBytes(uniformBytes);
	}

	protected Scalar hashToScalar(byte[] hash, byte[] customDST) {
		final var dst = ObjectUtils.defaultIfNull(customDST, Arrays.concatenate(Labels.HASH_TO_SCALAR, context()));
		final var uniformBytes = ExpandMessage.expandMessageXMD(new SHA512Digest(), hash, dst, HASH_OUTPUT_SIZE);
		return Scalar.fromBytesModOrderWide(uniformBytes);
	}

	public Scalar randomScalar() {
		final var uniformBytes = RandomUtils.secureStrong().randomBytes(HASH_OUTPUT_SIZE);
		return Scalar.fromBytesModOrderWide(uniformBytes);
	}

	public KeyPair randomKeyPair() {
		final var secretScalar  = randomScalar();
		final var publicElement = RistrettoElement.BASEPOINT.multiply(secretScalar);
		return new KeyPair(secretScalar.toByteArray(), publicElement.compress().toByteArray());
	}

	public KeyPair deriveKeyPair(byte[] seed, byte[] info) throws Exception {
		final var nullSafeInfo = ArrayUtils.nullToEmpty(info);
		final var deriveInput = Arrays.concatenate(seed, I2OSP(nullSafeInfo.length, 2), nullSafeInfo);
		final var deriveDST = Arrays.concatenate(Labels.DERIVE_KEYPAIR, context());

		int counter = 0;
		Scalar secretScalar = Scalar.ZERO;
		while (Scalar.ZERO.ctEquals(secretScalar) == 1) {
			if (counter > 255) throw new Exception("Failed to derive secret key");
			secretScalar = hashToScalar(Arrays.concatenate(deriveInput, I2OSP(counter, 1)), deriveDST);
			counter++;
		}

		final var secretKey = secretScalar.toByteArray();
		final var publicKey = RistrettoElement.BASEPOINT.multiply(secretScalar).compress().toByteArray();
		return new KeyPair(secretKey, publicKey);
	}

	protected byte[] hash(byte[] input) {
		final var hash = new SHA512Digest();
		hash.update(input, 0, input.length);

		final var output = new byte[hash.getDigestSize()];
		hash.doFinal(output, 0);
		return output;
	}

	protected byte[] I2OSP(long input, int size) {
		return BigIntegers.asUnsignedByteArray(size, BigInteger.valueOf(input));
	}

	public static final record Proof(byte[] c, byte[] s){
		public static Proof fromBytes(byte[] input) {
			final var c = Arrays.copyOfRange(input, 0, SCALAR_SIZE);
			final var s = Arrays.copyOfRange(input, SCALAR_SIZE, input.length);
			return new Proof(c, s);
		}

		public byte[] toByteArray() {
			return Arrays.concatenate(c, s);
		}
	}

	protected static final record CompositesResult(RistrettoElement M, RistrettoElement Z) {}

	protected CompositesResult computeCompositesFast(Scalar k, RistrettoElement B, RistrettoElement[] C, RistrettoElement[] D) {
		final var bm = encodeElement(B);
		final var seedDST = Arrays.concatenate(Labels.SEED_DST_PREFIX, context());
		final var seed = hash(Arrays.concatenate(
			I2OSP(bm.length, 2), bm,
			I2OSP(seedDST.length, 2), seedDST));

		var M = RistrettoElement.IDENTITY;
		for (var i = 0; i < C.length; i++) {
			final var Ci = encodeElement(C[i]);
			final var Di = encodeElement(D[i]);
			final var di = hashToScalar(Arrays.concatenate(new byte[][]{
				I2OSP(seed.length, 2), seed,
				I2OSP(i, 2),
				I2OSP(Ci.length, 2), Ci,
				I2OSP(Di.length, 2), Di,
				Labels.COMPOSITE
			}), null);

			M = C[i].multiply(di).add(M);
		}

		final var Z = M.multiply(k);

		return new CompositesResult(M, Z);
	}

	protected CompositesResult computeComposites(RistrettoElement B, RistrettoElement[] C, RistrettoElement[] D) {
		final var bm = encodeElement(B);
		final var seedDST = Arrays.concatenate(Labels.SEED_DST_PREFIX, context());
		final var seed = hash(Arrays.concatenate(
			I2OSP(bm.length, 2), bm,
			I2OSP(seedDST.length, 2), seedDST));

		var M = RistrettoElement.IDENTITY;
		var Z = RistrettoElement.IDENTITY;
		for (var i = 0; i < C.length; i++) {
			final var Ci = encodeElement(C[i]);
			final var Di = encodeElement(D[i]);
			final var di = hashToScalar(Arrays.concatenate(new byte[][]{
				I2OSP(seed.length, 2), seed,
				I2OSP(i, 2),
				I2OSP(Ci.length, 2), Ci,
				I2OSP(Di.length, 2), Di,
				Labels.COMPOSITE
			}), null);

			M = C[i].multiply(di).add(M);
			Z = D[i].multiply(di).add(Z);
		}

		return new CompositesResult(M, Z);
	}

	protected Proof generateProof(Scalar k, RistrettoElement A, RistrettoElement B, RistrettoElement[] C, RistrettoElement[] D, Scalar proofRandomScalar) {
		final var MZ = computeCompositesFast(k, B, C, D);
		final var M = MZ.M();
		final var Z = MZ.Z();

		final var r = ObjectUtils.getIfNull(proofRandomScalar, () -> randomScalar());
		final var t2 = A.multiply(r);
		final var t3 = M.multiply(r);

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

		final var c = hashToScalar(challengeTranscript, null);
		final var s = r.subtract(c.multiply(k));
		return new Proof(encodeScalar(c), encodeScalar(s));
	}

	protected Proof generateProof(Scalar k, RistrettoElement A, RistrettoElement B, RistrettoElement[] C, RistrettoElement[] D) {
		return generateProof(k, A, B, C, D, null);
	}

	protected boolean verifyProof(RistrettoElement A, RistrettoElement B, RistrettoElement[] C, RistrettoElement[] D, Proof proof) throws Exception {
		final var MZ = computeComposites(B, C, D);
		final var M = MZ.M();
		final var Z = MZ.Z();
		final var c = decodeScalar(proof.c());
		final var s = decodeScalar(proof.s());

		final var t2 = A.multiply(s).add(B.multiply(c));
		final var t3 = M.multiply(s).add(Z.multiply(c));

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

		final var expectedC = hashToScalar(challengeTranscript, null);
		return expectedC.ctEquals(c) == 1;
	}
}
