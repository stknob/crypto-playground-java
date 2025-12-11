/**
 * RFC 9497 OPRF implementation for Ristretto255
 *
 * Copyright (c) 2025 Stefan Knoblich <stkn@bitplumber.de>
 *
 * SPDX-License-Identifier: MIT
 */
package de.bitplumber.crypto.oprf.ristretto255;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import de.bitplumber.crypto.oprf.ristretto255.AbstractRistretto255.Proof;

class Ristretto255VOPRFTest {
	private static final record RFC9497TestVector(byte[] seed, byte[] keyInfo, byte[] secretKey, byte[] publicKey, byte[] input,
		byte[] blind, byte[] blindedElement, byte[] evaluationElement, byte[] proof, byte[] proofRandomScalar, byte[] output) {}

	private static final RFC9497TestVector[] VOPRF_TEST_VECTORS = new RFC9497TestVector[]{
		// ristretto255-SHA512 - VOPRF - Test Vector 1, Batch Size 1
		new RFC9497TestVector(
			Hex.decode("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3"),
			Hex.decode("74657374206b6579"),
			Hex.decode("e6f73f344b79b379f1a0dd37e07ff62e38d9f71345ce62ae3a9bc60b04ccd909"),
			Hex.decode("c803e2cc6b05fc15064549b5920659ca4a77b2cca6f04f6b357009335476ad4e"),
			Hex.decode("00"),
			Hex.decode("64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706"),
			Hex.decode("863f330cc1a1259ed5a5998a23acfd37fb4351a793a5b3c090b642ddc439b945"),
			Hex.decode("aa8fa048764d5623868679402ff6108d2521884fa138cd7f9c7669a9a014267e"),
			Hex.decode("ddef93772692e535d1a53903db24367355cc2cc78de93b3be5a8ffcc6985dd066d4346421d17bf5117a2a1ff0fcb2a759f58a539dfbe857a40bce4cf49ec600d"),
			Hex.decode("222a5e897cf59db8145db8d16e597e8facb80ae7d4e26d9881aa6f61d645fc0e"),
			Hex.decode("b58cfbe118e0cb94d79b5fd6a6dafb98764dff49c14e1770b566e42402da1a7da4d8527693914139caee5bd03903af43a491351d23b430948dd50cde10d32b3c")
		),
		// ristretto255-SHA512 - VOPRF - Test Vector 2, Batch Size 1
		new RFC9497TestVector(
			Hex.decode("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3"),
			Hex.decode("74657374206b6579"),
			Hex.decode("e6f73f344b79b379f1a0dd37e07ff62e38d9f71345ce62ae3a9bc60b04ccd909"),
			Hex.decode("c803e2cc6b05fc15064549b5920659ca4a77b2cca6f04f6b357009335476ad4e"),
			Hex.decode("5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"),
			Hex.decode("64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706"),
			Hex.decode("cc0b2a350101881d8a4cba4c80241d74fb7dcbfde4a61fde2f91443c2bf9ef0c"),
			Hex.decode("60a59a57208d48aca71e9e850d22674b611f752bed48b36f7a91b372bd7ad468"),
			Hex.decode("401a0da6264f8cf45bb2f5264bc31e109155600babb3cd4e5af7d181a2c9dc0a67154fabf031fd936051dec80b0b6ae29c9503493dde7393b722eafdf5a50b02"),
			Hex.decode("222a5e897cf59db8145db8d16e597e8facb80ae7d4e26d9881aa6f61d645fc0e"),
			Hex.decode("8a9a2f3c7f085b65933594309041fc1898d42d0858e59f90814ae90571a6df60356f4610bf816f27afdd84f47719e480906d27ecd994985890e5f539e7ea74b6")
		),
	};

	@Test
	void testRFC9497TestVectors() {
		for (final var vector : VOPRF_TEST_VECTORS) {
			final var voprf = new Ristretto255VOPRF(new Ristretto255VOPRF.VoprfParameter()
				.withBlindRandomScalar(vector.blind())
				.withProofRandomScalar(vector.proofRandomScalar()));
			final var keypair = assertDoesNotThrow(() -> voprf.deriveKeyPair(vector.seed(), vector.keyInfo()));
			assertArrayEquals(vector.secretKey(), keypair.secretKey(), "secret key");
			assertArrayEquals(vector.publicKey(), keypair.publicKey(), "public key");

			final var blindResult = assertDoesNotThrow(() -> voprf.blind(vector.input()));
			assertArrayEquals(vector.blindedElement(), voprf.encodeElement(blindResult.blindedElement()), "blindedElement");

			final var blindEvaluateResult = assertDoesNotThrow(() -> voprf.blindEvaluate(keypair.secretKey(), keypair.publicKey(), blindResult.blindedElement()));
			assertArrayEquals(vector.evaluationElement(), voprf.encodeElement(blindEvaluateResult.evaluatedElement()), "evaluatedElement");
			assertArrayEquals(vector.proof(), blindEvaluateResult.proof(), "proof");

			final var finalizeResult = assertDoesNotThrow(() -> voprf.finalize(vector.input(), blindResult.blind(), blindEvaluateResult.evaluatedElement(),
				blindResult.blindedElement(), vector.publicKey(), Proof.fromBytes(vector.proof())));
			assertArrayEquals(vector.output(), finalizeResult, "finalize output");

			final var evaluateResult = assertDoesNotThrow(() -> voprf.evaluate(keypair.secretKey(), vector.input()));
			assertArrayEquals(vector.output(), evaluateResult, "evaluate output");
		}
	}
}
