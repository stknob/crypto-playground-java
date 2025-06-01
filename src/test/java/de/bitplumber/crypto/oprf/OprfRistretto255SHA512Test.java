package de.bitplumber.crypto.oprf;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import de.bitplumber.crypto.oprf.ristretto255.OprfRistretto255Sha512;

class OprfRistretto255SHA512Test {
	private static final record RFC9497TestVector(byte[] seed, byte[] keyInfo, byte[] secretKey, byte[] input,
		byte[] blind, byte[] blindedElement, byte[] evaluationElement, byte[] output) {}

	private static final RFC9497TestVector[] RFC9497TestVectors = new RFC9497TestVector[]{
		// RFC 9497 - ristretto255-SHA512 - OPRF - Test Vector 1, Batch Size 1
		new RFC9497TestVector(
			Hex.decode("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3"),
			Hex.decode("74657374206b6579"),
			Hex.decode("5ebcea5ee37023ccb9fc2d2019f9d7737be85591ae8652ffa9ef0f4d37063b0e"),
			Hex.decode("00"),
			Hex.decode("64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706"),
			Hex.decode("609a0ae68c15a3cf6903766461307e5c8bb2f95e7e6550e1ffa2dc99e412803c"),
			Hex.decode("7ec6578ae5120958eb2db1745758ff379e77cb64fe77b0b2d8cc917ea0869c7e"),
			Hex.decode("527759c3d9366f277d8c6020418d96bb393ba2afb20ff90df23fb7708264e2f3ab9135e3bd69955851de4b1f9fe8a0973396719b7912ba9ee8aa7d0b5e24bcf6")
		),
		// RFC 9497 - ristretto255-SHA512 - OPRF - Test Vector 2, Batch Size 1
		new RFC9497TestVector(
			Hex.decode("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3"),
			Hex.decode("74657374206b6579"),
			Hex.decode("5ebcea5ee37023ccb9fc2d2019f9d7737be85591ae8652ffa9ef0f4d37063b0e"),
			Hex.decode("5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"),
			Hex.decode("64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706"),
			Hex.decode("da27ef466870f5f15296299850aa088629945a17d1f5b7f5ff043f76b3c06418"),
			Hex.decode("b4cbf5a4f1eeda5a63ce7b77c7d23f461db3fcab0dd28e4e17cecb5c90d02c25"),
			Hex.decode("f4a74c9c592497375e796aa837e907b1a045d34306a749db9f34221f7e750cb4f2a6413a6bf6fa5e19ba6348eb673934a722a7ede2e7621306d18951e7cf2c73")
		),
	};

	@Test
	void testRFC9497TestVectors() {
		final var oprf = new OprfRistretto255Sha512();

		for (final var vector : RFC9497TestVectors) {
			final var keypair = assertDoesNotThrow(() -> oprf.deriveKeypair(vector.seed(), vector.keyInfo()));
			assertArrayEquals(vector.secretKey(), keypair.secretKey());

			final var blindResult = oprf.blind(vector.input(), vector.blind());
			assertArrayEquals(vector.blindedElement(), oprf.encodeElement(blindResult.blindedElement()));

			final var blindEvaluateResult = oprf.blindEvaluate(keypair.secretKey(), blindResult.blindedElement());
			assertArrayEquals(vector.evaluationElement(), oprf.encodeElement(blindEvaluateResult));

			final var finalizeResult = oprf.finalize(vector.input(), blindResult.blind(), blindEvaluateResult);
			assertArrayEquals(vector.output(), finalizeResult);

			final var evaluateResult = oprf.evaluate(keypair.secretKey(), vector.input());
			assertArrayEquals(vector.output(), evaluateResult);
		}
	}
}
