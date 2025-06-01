package de.bitplumber.crypto.oprf.ristretto255;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

import org.bouncycastle.util.Arrays;

import com.weavechain.curve25519.RistrettoElement;
import com.weavechain.curve25519.Scalar;

import de.bitplumber.crypto.oprf.Labels;
import de.bitplumber.crypto.oprf.Modes;
import de.bitplumber.crypto.oprf.Poprf;
import de.bitplumber.crypto.oprf.ristretto255.VoprfRistretto255Sha512.VoprfParameter;

public class PoprfRistretto255Sha512 extends AbstractRistretto255Sha512 implements Poprf<Scalar, RistrettoElement, PoprfRistretto255Sha512.BlindResult, PoprfRistretto255Sha512.BlindEvaluateResult, PoprfRistretto255Sha512.Proof> {
	public static record BlindResult(Scalar blind, RistrettoElement blindedElement, RistrettoElement tweakedKey) {}
	public static final record BlindEvaluateResult(RistrettoElement evaluatedElement, byte[] proof) {}
	private final PoprfParameter params;

	private static final byte[] CONTEXT = Arrays.concatenate(new byte[][]{
		Labels.CONTEXT_PREFIX, Modes.POPRF,
		("-" + SUITE_ID).getBytes(StandardCharsets.UTF_8),
	});

	protected byte[] context() {
		return CONTEXT;
	}

	public PoprfRistretto255Sha512() {
		this.params = DEFAULT_PARAMETER;
	}

	public PoprfRistretto255Sha512(PoprfParameter params) {
		this.params = params;
	}

	public static final PoprfParameter DEFAULT_PARAMETER = new PoprfParameter();
	public static final class PoprfParameter {
		protected byte[] proofRandomScalar;
		protected byte[] blindRandomScalar;

		public byte[] blindRandomScalar() {
			return blindRandomScalar;
		}

		public byte[] proofRandomScalar() {
			return proofRandomScalar;
		}

		/**
		 * Set a custom domain separation label for key derivation
		 * <strong>For unittests only!</strong>
		 * @param label
		 * @return
		 */
		public PoprfParameter withBlindRandomScalar(byte[] blindRandomScalar) {
			Objects.requireNonNull(blindRandomScalar, "blindRandomScalar");
			this.blindRandomScalar = blindRandomScalar;
			return this;
		}

		/**
		 * Set a custom domain separation label for key derivation
		 * <strong>For unittests only!</strong>
		 * @param label
		 * @return
		 */
		public PoprfParameter withProofRandomScalar(byte[] proofRandomScalar) {
			Objects.requireNonNull(proofRandomScalar, "proofRandomScalar");
			this.proofRandomScalar = proofRandomScalar;
			return this;
		}
	}

	private BlindResult doBlind(byte[] input, byte[] info, byte[] publicKey, Scalar blind) throws Exception {
		final var pkS = decodeElement(publicKey);
		final var framedInfo = Arrays.concatenate(Labels.INFO, I2OSP(info.length, 2), info);
		final var m = hashToScalar(framedInfo, null);
		final var T = RistrettoElement.BASEPOINT.multiply(m);
		final var tweakedKey = T.add(pkS);
		if (tweakedKey.ctEquals(RistrettoElement.IDENTITY) == 1)
			throw new IllegalArgumentException("InvalidInputError");

		final var inputElement = hashToGroup(input, null);
		if (inputElement.ctEquals(RistrettoElement.IDENTITY) == 1)
			throw new IllegalArgumentException("InvalidInputError");

		final var blindedElement = inputElement.multiply(blind);
		return new BlindResult(blind, blindedElement, tweakedKey);
	}

	public BlindResult blind(byte[] input, byte[] info, byte[] publicKey) throws Exception {
		return doBlind(input, info, publicKey, params.blindRandomScalar() == null ? randomScalar() : decodeScalar(params.blindRandomScalar()));
	}

	public BlindEvaluateResult blindEvaluate(byte[] secretKey, RistrettoElement blindedElement, byte[] info) throws Exception {
		final var skS = decodeScalar(secretKey);
		final var framedInfo = Arrays.concatenate(Labels.INFO, I2OSP(info.length, 2), info);
		final var m = hashToScalar(framedInfo, null);
		final var t = skS.add(m);
		if (t.ctEquals(Scalar.ZERO) == 1)
			throw new IllegalArgumentException("InverseError");

		final var evaluatedElement = blindedElement.multiply(t.invert());
		final var tweakedKey = RistrettoElement.BASEPOINT.multiply(t);
		final var blindedElements  = new RistrettoElement[]{ blindedElement };
		final var evaluatedElements = new RistrettoElement[]{ evaluatedElement };
		final var proof = generateProof(t, RistrettoElement.BASEPOINT, tweakedKey, evaluatedElements, blindedElements,
			params.proofRandomScalar() == null ? null : decodeScalar(params.proofRandomScalar()));
		return new BlindEvaluateResult(evaluatedElement, proof.toByteArray());
	}

	public byte[] finalize(byte[] input, Scalar blind, RistrettoElement evaluatedElement, RistrettoElement blindedElement, Proof proof, byte[] info, RistrettoElement tweakedKey) throws Exception {
		final var blindedElements = new RistrettoElement[]{ blindedElement };
		final var evaluatedElements = new RistrettoElement[]{ evaluatedElement };
		if (!verifyProof(RistrettoElement.BASEPOINT, tweakedKey, evaluatedElements, blindedElements, proof))
			throw new Exception("Failed to verify proof");

		final var invBlind = blind.invert();
		final var n = evaluatedElement.multiply(invBlind);
		final var unblindedElement = encodeElement(n);
		return hash(Arrays.concatenate(new byte[][]{
			I2OSP(input.length, 2), input,
			I2OSP(info.length, 2), info,
			I2OSP(unblindedElement.length, 2), unblindedElement,
			Labels.FINALIZE
		}));
	}

	public byte[] evaluate(byte[] secretKey, byte[] input, byte[] info) {
		final var inputElement = hashToGroup(input, null);
		if (inputElement.ctEquals(RistrettoElement.IDENTITY) == 1)
			throw new IllegalArgumentException("InvalidInputError");

		final var skS = decodeScalar(secretKey);
		final var framedInfo = Arrays.concatenate(Labels.INFO, I2OSP(info.length, 2), info);
		final var m = hashToScalar(framedInfo, null);
		final var t = skS.add(m);
		if (t.ctEquals(Scalar.ZERO) == 1)
			throw new IllegalArgumentException("InverseError");

		final var evaluatedElement = inputElement.multiply(t.invert());
		final var issuedElement = encodeElement(evaluatedElement);

		return hash(Arrays.concatenate(new byte[][]{
			I2OSP(input.length, 2), input,
			I2OSP(info.length, 2), info,
			I2OSP(issuedElement.length, 2), issuedElement,
			Labels.FINALIZE
		}));
	}
}
