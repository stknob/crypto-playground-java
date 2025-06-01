package de.bitplumber.crypto.nopaque;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import de.bitplumber.crypto.nopaque.ristretto255.Client;
import de.bitplumber.crypto.nopaque.ristretto255.Server;
import de.bitplumber.crypto.nopaque.ristretto255.AbstractRistretto255Sha512.RegistrationRequest;
import de.bitplumber.crypto.nopaque.ristretto255.Server.RegistrationRecord;
import de.bitplumber.crypto.oprf.KeyPair;

class NopaqueRistretto255SHA512Test {
	private static final record OpaqueDraftTestVector(byte[] clientIdentity, byte[] serverIdentity, byte[] context, byte[] oprfSeed, byte[] credentialId, byte[] password, byte[] envelopeNonce, byte[] maskingNonce,
		byte[] serverSecretKey, byte[] serverPublicKey, byte[] blindRegistration, byte[] blindLogin, byte[] clientPublicKey, byte[] authKey, byte[] randomizedPassword, byte[] envelope, byte[] handshakeSecret,
		byte[] oprfKey, byte[] registrationRequest, byte[] registrationResponse, byte[] registrationUpload, byte[] recoverRequest, byte[] recoverResponse, byte[] exportKey) {}

	private static final OpaqueDraftTestVector[] opaqueDraftTestVectors = new OpaqueDraftTestVector[]{
		// D.1.1. OPAQUE-3DH Real Test Vector 1
		new OpaqueDraftTestVector(
			// Input parameters
			null,
			null,
			Hex.decode("4f50415155452d504f43"),
			Hex.decode("f433d0227b0b9dd54f7c4422b600e764e47fb503f1f9a0f0a47c6606b054a7fdc65347f1a08f277e22358bbabe26f823fca82c7848e9a75661f4ec5d5c1989ef"),
			Hex.decode("31323334"),
			Hex.decode("436f7272656374486f72736542617474657279537461706c65"),
			Hex.decode("ac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfec"),
			Hex.decode("38fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6d"),
			Hex.decode("47451a85372f8b3537e249d7b54188091fb18edde78094b43e2ba42b5eb89f0d"),
			Hex.decode("b2fe7af9f48cc502d016729d2fe25cdd433f2c4bc904660b2a382c9b79df1a78"),
			Hex.decode("76cfbfe758db884bebb33582331ba9f159720ca8784a2a070a265d9c2d6abe01"),
			Hex.decode("6ecc102d2e7a7cf49617aad7bbe188556792d4acd60a1a8a8d2b65d4b0790308"),
			// Intermediate values
			Hex.decode("76a845464c68a5d2f7e442436bb1424953b17d3e2e289ccbaccafb57ac5c3675"),
			Hex.decode("6cd32316f18d72a9a927a83199fa030663a38ce0c11fbaef82aa90037730494fc555c4d49506284516edd1628c27965b7555a4ebfed2223199f6c67966dde822"),
			Hex.decode("aac48c25ab036e30750839d31d6e73007344cb1155289fb7d329beb932e9adeea73d5d5c22a0ce1952f8aba6d66007615cd1698d4ac85ef1fcf150031d1435d9"),
			Hex.decode("ac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfec634b0f5b96109c198a8027da51854c35bee90d1e1c781806d07d49b76de6a28b8d9e9b6c93b9f8b64d16dddd9c5bfb5fea48ee8fd2f75012a8b308605cdd8ba5"),
			Hex.decode("81263cb85a0cfa12450f0f388de4e92291ec4c7c7a0878b624550ff528726332f1298fc6cc822a432c89504347c7a2ccd70316ae3da6a15e0399e6db3f7c1b12"),
			Hex.decode("5d4c6a8b7c7138182afb4345d1fae6a9f18a1744afbcc3854f8f5a2b4b4c6d05"),
			// Output values
			Hex.decode("5059ff249eb1551b7ce4991f3336205bde44a105a032e747d21bf382e75f7a71"),
			Hex.decode("7408a268083e03abc7097fc05b587834539065e86fb0c7b6342fcf5e01e5b019b2fe7af9f48cc502d016729d2fe25cdd433f2c4bc904660b2a382c9b79df1a78"),
			Hex.decode("76a845464c68a5d2f7e442436bb1424953b17d3e2e289ccbaccafb57ac5c36751ac5844383c7708077dea41cbefe2fa15724f449e535dd7dd562e66f5ecfb95864eadddec9db5874959905117dad40a4524111849799281fefe3c51fa82785c5ac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfec634b0f5b96109c198a8027da51854c35bee90d1e1c781806d07d49b76de6a28b8d9e9b6c93b9f8b64d16dddd9c5bfb5fea48ee8fd2f75012a8b308605cdd8ba5"),
			Hex.decode("c4dedb0ba6ed5d965d6f250fbe554cd45cba5dfcce3ce836e4aee778aa3cd44d"),
			Hex.decode("7e308140890bcde30cbcea28b01ea1ecfbd077cff62c4def8efa075aabcbb47138fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6dd6ec60bcdb26dc455ddf3e718f1020490c192d70dfc7e403981179d8073d1146a4f9aa1ced4e4cd984c657eb3b54ced3848326f70331953d91b02535af44d9fedc80188ca46743c52786e0382f95ad85c08f6afcd1ccfbff95e2bdeb015b166c6b20b92f832cc6df01e0b86a7efd92c1c804ff865781fa93f2f20b446c8371b6"),
			Hex.decode("1ef15b4fa99e8a852412450ab78713aad30d21fa6966c9b8c9fb3262a970dc62950d4dd4ed62598229b1b72794fc0335199d9f7fcc6eaedde92cc04870e63f16")
		),
		//
		new OpaqueDraftTestVector(
			// Input parameters
			Hex.decode("616c696365"),
			Hex.decode("626f62"),
			Hex.decode("4f50415155452d504f43"),
			Hex.decode("f433d0227b0b9dd54f7c4422b600e764e47fb503f1f9a0f0a47c6606b054a7fdc65347f1a08f277e22358bbabe26f823fca82c7848e9a75661f4ec5d5c1989ef"),
			Hex.decode("31323334"),
			Hex.decode("436f7272656374486f72736542617474657279537461706c65"),
			Hex.decode("ac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfec"),
			Hex.decode("38fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6d"),
			Hex.decode("47451a85372f8b3537e249d7b54188091fb18edde78094b43e2ba42b5eb89f0d"),
			Hex.decode("b2fe7af9f48cc502d016729d2fe25cdd433f2c4bc904660b2a382c9b79df1a78"),
			Hex.decode("76cfbfe758db884bebb33582331ba9f159720ca8784a2a070a265d9c2d6abe01"),
			Hex.decode("6ecc102d2e7a7cf49617aad7bbe188556792d4acd60a1a8a8d2b65d4b0790308"),
			// Intermediate values
			Hex.decode("76a845464c68a5d2f7e442436bb1424953b17d3e2e289ccbaccafb57ac5c3675"),
			Hex.decode("6cd32316f18d72a9a927a83199fa030663a38ce0c11fbaef82aa90037730494fc555c4d49506284516edd1628c27965b7555a4ebfed2223199f6c67966dde822"),
			Hex.decode("aac48c25ab036e30750839d31d6e73007344cb1155289fb7d329beb932e9adeea73d5d5c22a0ce1952f8aba6d66007615cd1698d4ac85ef1fcf150031d1435d9"),
			Hex.decode("ac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfec1ac902dc5589e9a5f0de56ad685ea8486210ef41449cd4d8712828913c5d2b680b2b3af4a26c765cff329bfb66d38ecf1d6cfa9e7a73c222c6efe0d9520f7d7c"),
			Hex.decode("5e723bed1e5276de2503419eba9da61ead573109c401226832398c7e08155b885bfe7bc93451f9d887a0c1d0c19233e40a8e47b347a9ac3907f94032a4cff64f"),
			Hex.decode("5d4c6a8b7c7138182afb4345d1fae6a9f18a1744afbcc3854f8f5a2b4b4c6d05"),
			// Output values
			Hex.decode("5059ff249eb1551b7ce4991f3336205bde44a105a032e747d21bf382e75f7a71"),
			Hex.decode("7408a268083e03abc7097fc05b587834539065e86fb0c7b6342fcf5e01e5b019b2fe7af9f48cc502d016729d2fe25cdd433f2c4bc904660b2a382c9b79df1a78"),
			Hex.decode("76a845464c68a5d2f7e442436bb1424953b17d3e2e289ccbaccafb57ac5c36751ac5844383c7708077dea41cbefe2fa15724f449e535dd7dd562e66f5ecfb95864eadddec9db5874959905117dad40a4524111849799281fefe3c51fa82785c5ac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfec1ac902dc5589e9a5f0de56ad685ea8486210ef41449cd4d8712828913c5d2b680b2b3af4a26c765cff329bfb66d38ecf1d6cfa9e7a73c222c6efe0d9520f7d7c"),
			Hex.decode("c4dedb0ba6ed5d965d6f250fbe554cd45cba5dfcce3ce836e4aee778aa3cd44d"),
			Hex.decode("7e308140890bcde30cbcea28b01ea1ecfbd077cff62c4def8efa075aabcbb47138fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6dd6ec60bcdb26dc455ddf3e718f1020490c192d70dfc7e403981179d8073d1146a4f9aa1ced4e4cd984c657eb3b54ced3848326f70331953d91b02535af44d9fea502150b67fe36795dd8914f164e49f81c7688a38928372134b7dccd50e09f8fed9518b7b2f94835b3c4fe4c8475e7513f20eb97ff0568a39caee3fd6251876f"),
			Hex.decode("1ef15b4fa99e8a852412450ab78713aad30d21fa6966c9b8c9fb3262a970dc62950d4dd4ed62598229b1b72794fc0335199d9f7fcc6eaedde92cc04870e63f16")
		),
	};

	@Test
	void testOpaqueDraftTestVectors() {
		for (final var vector : opaqueDraftTestVectors) {
			final var clientParams = new Client.ClientParameter()
				.withCustomDeriveDhKeypairLabel("OPAQUE-DeriveDiffieHellmanKeyPair")
				.withEnvelopeNonce(vector.envelopeNonce())
				.withBlindRegistration(vector.blindRegistration())
				.withBlindRecover(vector.blindLogin());


			final var serverParams = new Server.ServerParameter()
				.withCustomDeriveKeypairLabel("OPAQUE-DeriveKeyPair")
				.withMaskingNonce(vector.maskingNonce());

			final var client = new Client(Stretcher.IDENTITY, clientParams);
			final var server = new Server(serverParams);

			/*
			 * Registration
			 */
			final var registerResult = client.createRegistrationRequest(vector.password());
			assertArrayEquals(vector.blindRegistration(), registerResult.blind());
			assertArrayEquals(vector.registrationRequest(), registerResult.request());

			final var credentialId = CredentialIdentifier.fromBytes(vector.credentialId());
			final var reqResponse = assertDoesNotThrow(() -> server.createRegistrationResponse(RegistrationRequest.fromBytes(registerResult.request()), vector.serverPublicKey(), credentialId, vector.oprfSeed()));
			assertArrayEquals(vector.registrationResponse(), reqResponse.toByteArray());

			final var finalizeResult = assertDoesNotThrow(() -> client.finalizeRegistrationRequest(reqResponse, vector.serverIdentity(), vector.clientIdentity()));
			assertArrayEquals(vector.exportKey(), finalizeResult.exportKey());
			assertArrayEquals(vector.registrationUpload(), finalizeResult.record());

			/*
			 * Recovery
			 */
			final var serverRecord = RegistrationRecord.fromBytes(finalizeResult.record());
			final var recoverRequest = client.createRecoverRequest(vector.password());
			assertArrayEquals(vector.recoverRequest(), recoverRequest.toByteArray());

			final var serverKeypair = new KeyPair(vector.serverSecretKey(), vector.serverPublicKey());
			final var recoverResponse = assertDoesNotThrow(() -> server.createRecoverResponse(serverKeypair, serverRecord, credentialId, vector.oprfSeed(), recoverRequest));
			assertArrayEquals(vector.recoverResponse(), recoverResponse.toByteArray());

			final var recoveredExportKey = assertDoesNotThrow(() -> client.finalizeRecoverRequest(recoverResponse, vector.serverIdentity(), vector.clientIdentity()));
			assertArrayEquals(vector.exportKey(), recoveredExportKey);
		}
	}


	@Test
	void testRoundtrip() {
		final var client = new Client(Stretcher.IDENTITY);
		final var server = new Server();

		/*
		 * Registration
		 */
		final var password = client.randomSecret();
		final var registerResult = client.createRegistrationRequest(password);
		final var registerRequest = registerResult.request();

		final var serverKeypair = server.randomKeypair();
		final var credentialId = CredentialIdentifier.fromBytes(client.randomSecret());
		final var oprfSeed = server.randomSeed();
		final var reqResponse = assertDoesNotThrow(() -> server.createRegistrationResponse(RegistrationRequest.fromBytes(registerRequest), serverKeypair.publicKey(), credentialId, oprfSeed));

		final var finalizeResult = assertDoesNotThrow(() -> client.finalizeRegistrationRequest(reqResponse, null, null));
		final var exportKey = finalizeResult.exportKey();
		final var clientRecord = finalizeResult.record();

		// Transfer clientRecord -> Server
		final var serverRecord = RegistrationRecord.fromBytes(clientRecord);

		/*
		 * Recover
		 */
		final var recoverRequest = client.createRecoverRequest(password);
		final var recoverResponse = assertDoesNotThrow(() -> server.createRecoverResponse(serverKeypair, serverRecord, credentialId, oprfSeed, recoverRequest));
		final var recoveredExportKey = assertDoesNotThrow(() -> client.finalizeRecoverRequest(recoverResponse, null, null));
		assertArrayEquals(exportKey, recoveredExportKey);
	}
}
