package de.bitplumber.crypto.oprf.ristretto255;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import de.bitplumber.crypto.oprf.ristretto255.AbstractRistretto255.Proof;

class Ristretto255PoprfTest {
	private static final record RFC9497TestVector(byte[] seed, byte[] keyInfo, byte[] secretKey, byte[] publicKey, byte[] info, byte[] input,
		byte[] blind, byte[] blindedElement, byte[] evaluationElement, byte[] proof, byte[] proofRandomScalar, byte[] output) {}

	private static final RFC9497TestVector[] POPRF_TEST_VECTORS = new RFC9497TestVector[]{
		// ristretto255-SHA512 - POPRF - Test Vector 1, Batch Size 1
		new RFC9497TestVector(
			Hex.decode("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3"),
			Hex.decode("74657374206b6579"),
			Hex.decode("145c79c108538421ac164ecbe131942136d5570b16d8bf41a24d4337da981e07"),
			Hex.decode("c647bef38497bc6ec077c22af65b696efa43bff3b4a1975a3e8e0a1c5a79d631"),
			Hex.decode("7465737420696e666f"),
			Hex.decode("00"),
			Hex.decode("64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706"),
			Hex.decode("c8713aa89241d6989ac142f22dba30596db635c772cbf25021fdd8f3d461f715"),
			Hex.decode("1a4b860d808ff19624731e67b5eff20ceb2df3c3c03b906f5693e2078450d874"),
			Hex.decode("41ad1a291aa02c80b0915fbfbb0c0afa15a57e2970067a602ddb9e8fd6b7100de32e1ecff943a36f0b10e3dae6bd266cdeb8adf825d86ef27dbc6c0e30c52206"),
			Hex.decode("222a5e897cf59db8145db8d16e597e8facb80ae7d4e26d9881aa6f61d645fc0e"),
			Hex.decode("ca688351e88afb1d841fde4401c79efebb2eb75e7998fa9737bd5a82a152406d38bd29f680504e54fd4587eddcf2f37a2617ac2fbd2993f7bdf45442ace7d221")
		),
		// ristretto255-SHA512 - POPRF - Test Vector 2, Batch Size 1
		new RFC9497TestVector(
			Hex.decode("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3"),
			Hex.decode("74657374206b6579"),
			Hex.decode("145c79c108538421ac164ecbe131942136d5570b16d8bf41a24d4337da981e07"),
			Hex.decode("c647bef38497bc6ec077c22af65b696efa43bff3b4a1975a3e8e0a1c5a79d631"),
			Hex.decode("7465737420696e666f"),
			Hex.decode("5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"),
			Hex.decode("64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706"),
			Hex.decode("f0f0b209dd4d5f1844dac679acc7761b91a2e704879656cb7c201e82a99ab07d"),
			Hex.decode("8c3c9d064c334c6991e99f286ea2301d1bde170b54003fb9c44c6d7bd6fc1540"),
			Hex.decode("4c39992d55ffba38232cdac88fe583af8a85441fefd7d1d4a8d0394cd1de77018bf135c174f20281b3341ab1f453fe72b0293a7398703384bed822bfdeec8908"),
			Hex.decode("222a5e897cf59db8145db8d16e597e8facb80ae7d4e26d9881aa6f61d645fc0e"),
			Hex.decode("7c6557b276a137922a0bcfc2aa2b35dd78322bd500235eb6d6b6f91bc5b56a52de2d65612d503236b321f5d0bebcbc52b64b92e426f29c9b8b69f52de98ae507")
		),
	};

	@Test
	void testRFC9497TestVectors() {
		for (final var vector : POPRF_TEST_VECTORS) {
			final var poprf = new Ristretto255Poprf(new Ristretto255Poprf.PoprfParameter()
				.withBlindRandomScalar(vector.blind())
				.withProofRandomScalar(vector.proofRandomScalar()));

			final var keypair = assertDoesNotThrow(() -> poprf.deriveKeyPair(vector.seed(), vector.keyInfo()));
			assertArrayEquals(vector.secretKey(), keypair.secretKey(), "secret key");
			assertArrayEquals(vector.publicKey(), keypair.publicKey(), "public key");

			final var blindResult = assertDoesNotThrow(() -> poprf.blind(vector.input(), vector.info(), vector.publicKey()));
			assertArrayEquals(vector.blindedElement(), poprf.encodeElement(blindResult.blindedElement()), "blindedElement");

			final var blindEvaluateResult = assertDoesNotThrow(() -> poprf.blindEvaluate(keypair.secretKey(), blindResult.blindedElement(), vector.info()));
			assertArrayEquals(vector.evaluationElement(), poprf.encodeElement(blindEvaluateResult.evaluatedElement()), "evaluatedElement");
			assertArrayEquals(vector.proof(), blindEvaluateResult.proof(), "proof");

			final var finalizeResult = assertDoesNotThrow(() -> poprf.finalize(vector.input(), blindResult.blind(), blindEvaluateResult.evaluatedElement(), blindResult.blindedElement(),
				Proof.fromBytes(blindEvaluateResult.proof()), vector.info(), blindResult.tweakedKey()));
			assertArrayEquals(vector.output(), finalizeResult, "finalize output");

			final var evaluateResult = assertDoesNotThrow(() -> poprf.evaluate(keypair.secretKey(), vector.input(), vector.info()));
			assertArrayEquals(vector.output(), evaluateResult, "evaluate output");
		}
	}
}
