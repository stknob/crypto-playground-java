/**
 * RFC 9497 OPRF implementation for Bouncy Castle EC
 *
 * Copyright (c) 2025 Stefan Knoblich <stkn@bitplumber.de>
 *
 * SPDX-License-Identifier: MIT
 */
package de.bitplumber.crypto.oprf.bc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

import org.bouncycastle.crypto.Xof;
import org.bouncycastle.crypto.digests.CSHAKEDigest;
import org.bouncycastle.util.encoders.Hex;

abstract class GenericOprfTestBase {
	protected static final record RFC9497OprfTestVector(byte[] seed, byte[] keyInfo, byte[] secretKey, byte[] input,
		byte[] blind, byte[] blindedElement, byte[] evaluationElement, byte[] output) {}

	protected void runTestVectors(ECCurveOprf oprf, RFC9497OprfTestVector[] vectors) {
		for (final var vector : vectors) {
			final var keypair = assertDoesNotThrow(() -> oprf.deriveKeyPair(vector.seed(), vector.keyInfo()));
			// assertArrayEquals(vector.secretKey(), keypair.secretKey(), "secretKey");
			assertArrayEquals(vector.secretKey(), keypair.secretKey(), String.format("secretKey does not match, expected: '%s', got: '%s'",
				Hex.toHexString(vector.secretKey()), Hex.toHexString(keypair.secretKey())
			));

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

	protected void runTestVectors(ECCurvePoprf poprf, RFC9497PoprfTestVector[] vectors) {
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

	protected void runTestVectors(ECCurveVoprf voprf, RFC9497VoprfTestVector[] vectors) {
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

	protected static final int DEFAULT_RANDOM_ROUNDS = 100;

	protected void runRandomizedRountrip(ECCurveOprf oprf, Integer rounds) {
		final var numRounds = Objects.requireNonNullElse(rounds, DEFAULT_RANDOM_ROUNDS).intValue();
		final var seed = Hex.decode("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3");
		final var keyInfo = Hex.decode("74657374206b6579");
		final var keySeed = new byte[32];
		final var input   = new byte[32];

		final var hash = hashXOF(seed, null);
		for (int i = 0; i < numRounds; i++) {
			hash.doOutput(keySeed, 0, keySeed.length);
			hash.doOutput(input,   0, input.length);

			final var keypair = assertDoesNotThrow(() -> oprf.deriveKeyPair(keySeed, keyInfo));
			final var blindResult = assertDoesNotThrow(() -> oprf.blind(input));
			final var blindEvaluateResult = assertDoesNotThrow(() -> oprf.blindEvaluate(keypair.secretKey(), blindResult.blindedElement()));
			final var finalizeResult = assertDoesNotThrow(() -> oprf.finalize(input, blindResult.blind(), blindEvaluateResult));
			final var evaluateResult = assertDoesNotThrow(() -> oprf.evaluate(keypair.secretKey(), input));
			assertArrayEquals(finalizeResult, evaluateResult, "evaluate and finalize outputs do not match");
		}
	}

	protected void runRandomizedRountrip(ECCurveOprf oprf) {
		runRandomizedRountrip(oprf, null);
	}


	protected void runRandomizedRountrip(ECCurvePoprf poprf, Integer rounds) {
		final var numRounds = Objects.requireNonNullElse(rounds, DEFAULT_RANDOM_ROUNDS).intValue();
		final var seed = Hex.decode("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3");
		final var info = Hex.decode("7465737420696e666f");
		final var keyInfo = Hex.decode("74657374206b6579");
		final var keySeed = new byte[32];
		final var input   = new byte[32];

		final var hash = hashXOF(seed, null);
		for (int i = 0; i < numRounds; i++) {
			hash.doOutput(keySeed, 0, keySeed.length);
			hash.doOutput(input,   0, input.length);

			final var keypair = assertDoesNotThrow(() -> poprf.deriveKeyPair(keySeed, keyInfo));
			final var blindResult = assertDoesNotThrow(() -> poprf.blind(input, info, keypair.publicKey()));
			final var blindEvaluateResult = assertDoesNotThrow(() -> poprf.blindEvaluate(keypair.secretKey(), blindResult.blindedElement(), info));
			final var finalizeResult = assertDoesNotThrow(() -> poprf.finalize(input, blindResult.blind(), blindEvaluateResult.evaluatedElement(), blindResult.blindedElement(), poprf.decodeProof(blindEvaluateResult.proof()), info, blindResult.tweakedKey()));
			final var evaluateResult = assertDoesNotThrow(() -> poprf.evaluate(keypair.secretKey(), input, info));
			assertArrayEquals(finalizeResult, evaluateResult, "evaluate and finalize outputs do not match");
		}
	}

	protected void runRandomizedRountrip(ECCurvePoprf poprf) {
		runRandomizedRountrip(poprf, null);
	}


	protected void runRandomizedRountrip(ECCurveVoprf voprf, Integer rounds) {
		final var numRounds = Objects.requireNonNullElse(rounds, DEFAULT_RANDOM_ROUNDS).intValue();
		final var seed = Hex.decode("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3");
		final var keyInfo = Hex.decode("74657374206b6579");
		final var keySeed = new byte[32];
		final var input   = new byte[32];

		final var hash = hashXOF(seed, null);
		for (int i = 0; i < numRounds; i++) {
			hash.doOutput(keySeed, 0, keySeed.length);
			hash.doOutput(input,   0, input.length);

			final var keypair = assertDoesNotThrow(() -> voprf.deriveKeyPair(keySeed, keyInfo));
			final var blindResult = assertDoesNotThrow(() -> voprf.blind(input));
			final var blindEvaluateResult = assertDoesNotThrow(() -> voprf.blindEvaluate(keypair.secretKey(), keypair.publicKey(), blindResult.blindedElement()));
			final var finalizeResult = assertDoesNotThrow(() -> voprf.finalize(input, blindResult.blind(), blindEvaluateResult.evaluatedElement(), blindResult.blindedElement(), keypair.publicKey(), voprf.decodeProof(blindEvaluateResult.proof())));
			final var evaluateResult = assertDoesNotThrow(() -> voprf.evaluate(keypair.secretKey(), input));
			assertArrayEquals(finalizeResult, evaluateResult, "evaluate and finalize outputs do not match");
		}
	}

	protected void runRandomizedRountrip(ECCurveVoprf voprf) {
		runRandomizedRountrip(voprf, null);
	}
}
