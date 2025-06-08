package de.bitplumber.crypto.oprf;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

import org.bouncycastle.crypto.Xof;
import org.bouncycastle.crypto.digests.CSHAKEDigest;

abstract class GenericOprfTestBase {
	protected static final record RFC9497OprfTestVector(byte[] seed, byte[] keyInfo, byte[] secretKey, byte[] input,
		byte[] blind, byte[] blindedElement, byte[] evaluationElement, byte[] output) {}

	protected void runOprfTestVectors(ECCurveOprf oprf, RFC9497OprfTestVector[] vectors) {
		for (final var vector : vectors) {
			final var keypair = assertDoesNotThrow(() -> oprf.deriveKeyPair(vector.seed(), vector.keyInfo()));
			assertArrayEquals(vector.secretKey(), keypair.secretKey(), "secretKey");

			final var blindResult = assertDoesNotThrow(() -> oprf.blind(vector.input(), vector.blind()));
			assertArrayEquals(vector.blindedElement(), oprf.encodeElement(blindResult.blindedElement()), "blindedElement");
			assertArrayEquals(vector.blind(), oprf.encodeScalar(blindResult.blind()), "blind");

			final var blindEvaluateResult = assertDoesNotThrow(() -> oprf.blindEvaluate(keypair.secretKey(), blindResult.blindedElement()));
			assertArrayEquals(vector.evaluationElement(), oprf.encodeElement(blindEvaluateResult), "evaluationElement");

			final var finalizeResult = assertDoesNotThrow(() -> oprf.finalize(vector.input(), blindResult.blind(), blindEvaluateResult));
			assertArrayEquals(vector.output(), finalizeResult, "finalize output");

			final var evaluateResult = assertDoesNotThrow(() -> oprf.evaluate(keypair.secretKey(), vector.input()));
			assertArrayEquals(vector.output(), evaluateResult, "evaluate output");
		}
	}

	protected static final record RFC9497PoprfTestVector(byte[] seed, byte[] keyInfo, byte[] secretKey, byte[] publicKey, byte[] info, byte[] input,
		byte[] blind, byte[] blindedElement, byte[] evaluationElement, byte[] proof, byte[] proofRandomScalar, byte[] output) {}

	protected void runPoprfTestVectors(ECCurvePoprf poprf, RFC9497PoprfTestVector[] vectors) {
		for (final var vector : vectors) {
			final var keypair = assertDoesNotThrow(() -> poprf.deriveKeyPair(vector.seed(), vector.keyInfo()));
			assertArrayEquals(vector.secretKey(), keypair.secretKey(), "secret key");
			assertArrayEquals(vector.publicKey(), keypair.publicKey(), "public key");

			final var blindResult = assertDoesNotThrow(() -> poprf.blind(vector.input(), vector.info(), vector.publicKey(), vector.blind()));
			assertArrayEquals(vector.blindedElement(), poprf.encodeElement(blindResult.blindedElement()), "blindedElement");

			final var blindEvaluateResult = assertDoesNotThrow(() -> poprf.blindEvaluate(keypair.secretKey(), blindResult.blindedElement(), vector.info(), vector.proofRandomScalar()));
			assertArrayEquals(vector.evaluationElement(), poprf.encodeElement(blindEvaluateResult.evaluatedElement()), "evaluatedElement");
			assertArrayEquals(vector.proof(), blindEvaluateResult.proof(), "proof");

			final var finalizeResult = assertDoesNotThrow(() -> poprf.finalize(vector.input(), blindResult.blind(), blindEvaluateResult.evaluatedElement(), blindResult.blindedElement(),
				poprf.decodeProof(blindEvaluateResult.proof()), vector.info(), blindResult.tweakedKey()));
			assertArrayEquals(vector.output(), finalizeResult, "finalize output");

			final var evaluateResult = assertDoesNotThrow(() -> poprf.evaluate(keypair.secretKey(), vector.input(), vector.info()));
			assertArrayEquals(vector.output(), evaluateResult, "evaluate output");
		}
	}

	protected static final record RFC9497VoprfTestVector(byte[] seed, byte[] keyInfo, byte[] secretKey, byte[] publicKey, byte[] input,
		byte[] blind, byte[] blindedElement, byte[] evaluationElement, byte[] proof, byte[] proofRandomScalar, byte[] output) {}

	protected void runVoprfTestVectors(ECCurveVoprf voprf, RFC9497VoprfTestVector[] vectors) {
		for (final var vector : vectors) {
			final var keypair = assertDoesNotThrow(() -> voprf.deriveKeyPair(vector.seed(), vector.keyInfo()));
			assertArrayEquals(vector.secretKey(), keypair.secretKey(), "secret key");
			assertArrayEquals(vector.publicKey(), keypair.publicKey(), "public key");

			final var blindResult = assertDoesNotThrow(() -> voprf.blind(vector.input(), vector.blind()));
			assertArrayEquals(vector.blindedElement(), voprf.encodeElement(blindResult.blindedElement()), "blindedElement");

			final var blindEvaluateResult = assertDoesNotThrow(() -> voprf.blindEvaluate(keypair.secretKey(), keypair.publicKey(), blindResult.blindedElement(), vector.proofRandomScalar()));
			assertArrayEquals(vector.evaluationElement(), voprf.encodeElement(blindEvaluateResult.evaluatedElement()), "evaluatedElement");
			assertArrayEquals(vector.proof(), blindEvaluateResult.proof(), "proof");

			final var finalizeResult = assertDoesNotThrow(() -> voprf.finalize(vector.input(), blindResult.blind(), blindEvaluateResult.evaluatedElement(),
				blindResult.blindedElement(), vector.publicKey(), voprf.decodeProof(vector.proof())));
			assertArrayEquals(vector.output(), finalizeResult, "finalize output");

			final var evaluateResult = assertDoesNotThrow(() -> voprf.evaluate(keypair.secretKey(), vector.input()));
			assertArrayEquals(vector.output(), evaluateResult, "evaluate output");
		}
	}

	/**
	 *
	 * @param seed
	 * @param dst
	 * @return
	 */
	protected Xof hashXOF(byte[] seed, byte[] dst) {
		final var h = new CSHAKEDigest(256, null, Objects.requireNonNullElse(dst, "".getBytes(StandardCharsets.UTF_8)));
		h.update(seed, 0, seed.length);
		return h;
	}
}
