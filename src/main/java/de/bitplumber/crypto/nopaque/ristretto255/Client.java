package de.bitplumber.crypto.nopaque.ristretto255;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.ObjectUtils;
import org.apache.commons.lang3.RandomUtils;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Bytes;

import de.bitplumber.crypto.nopaque.Labels;
import de.bitplumber.crypto.nopaque.Stretcher;

/**
 * Client implementation of NOPAQUE-Ristretto255-SHA512
 */
public class Client extends AbstractRistretto255 {
	/** Client-side state, used for registration and recover process to hold information required by steps */
	private static final record ClientState(byte[] secret, byte[] blind) {}
	private final ClientParameter params;
	private final Stretcher stretch;
	private ClientState state = null;

	public Client() {
		this.params = new ClientParameter();
		this.stretch = Stretcher.IDENTITY;
	}

	public Client(Stretcher stretch) {
		this.params = new ClientParameter();
		this.stretch = stretch;
	}

	public Client(Stretcher stretch, ClientParameter params) {
		this.stretch = stretch;
		this.params = params;
	}

	public static final ClientParameter DEFAULT_PARAMETER = new ClientParameter()
		.withCustomDeriveDhKeyPairLabel(Labels.NOPAQUE_DERIVE_DH_KEYPAIR);

	public static final class ClientParameter {
		protected byte[] customDeriveDhKeyPairLabel;
		protected byte[] envelopeNonce;
		protected byte[] blindRegistration;
		protected byte[] blindRecover;

		public byte[] customDeriveDhKeyPairLabel() {
			return customDeriveDhKeyPairLabel;
		}

		public byte[] envelopeNonce() {
			return envelopeNonce;
		}

		public byte[] blindRegistration() {
			return blindRegistration;
		}

		public byte[] blindRecover() {
			return blindRecover;
		}

		/**
		 * Set a custom domain separation label for the DH key derivation
		 * <strong>For unittests only!</strong>
		 * @param label
		 * @return
		 */
		public ClientParameter withCustomDeriveDhKeyPairLabel(byte[] label) {
			Objects.requireNonNull(label, "label");
			this.customDeriveDhKeyPairLabel = label;
			return this;
		}

		/**
		 * Set a custom domain separation label for the DH key derivation
		 * <strong>For unittests only!</strong>
		 * @param label
		 * @return
		 */
		public ClientParameter withCustomDeriveDhKeyPairLabel(String label) {
			Objects.requireNonNull(label, "label");
			this.customDeriveDhKeyPairLabel = label.getBytes(StandardCharsets.UTF_8);
			return this;
		}

		public ClientParameter withEnvelopeNonce(byte[] envelopeNonce) {
			Objects.requireNonNull(envelopeNonce, "envelopeNonce");
			this.envelopeNonce = envelopeNonce;
			return this;
		}

		public ClientParameter withBlindRegistration(byte[] blind) {
			Objects.requireNonNull(blind, "blind");
			this.blindRegistration = blind;
			return this;
		}

		public ClientParameter withBlindRecover(byte[] blind) {
			Objects.requireNonNull(blind, "blind");
			this.blindRecover = blind;
			return this;
		}
	}


	private static final record CleartextCredentials(byte[] serverIdentity, byte[] clientIdentity) {}
	private static final record StoreResult(byte[] envelope, byte[] clientPublicKey, byte[] maskingKey, byte[] exportKey) {}
	private static final record RecoverResult(byte[] exportKey) {}

	private CleartextCredentials createCleartextCredentials(byte[] serverPublicKey, byte[] clientPublicKey, byte[] serverIdentity, byte[] clientIdentity) {
		return new CleartextCredentials(
			ObjectUtils.defaultIfNull(serverIdentity, serverPublicKey),
			ObjectUtils.defaultIfNull(clientIdentity, clientPublicKey)
		);
	}

	private void clearArrays(byte[] ...args) {
		for (final byte[] arr : args) {
			Arrays.clear(arr);
		}
	}

	private StoreResult store(byte[] randomizedPassword, byte[] serverPublicKey, byte[] serverIdentity, byte[] clientIdentity) throws Exception {
		final var envelopeNonce = ObjectUtils.defaultIfNull(params.envelopeNonce(), RandomUtils.secureStrong().randomBytes(N_N));

		final var maskingKey = expand(randomizedPassword, Labels.MASKING_KEY, N_H);
		final var exportKey = expand(randomizedPassword, Arrays.concatenate(envelopeNonce, Labels.EXPORT_KEY), N_H);
		final var authKey = expand(randomizedPassword, Arrays.concatenate(envelopeNonce, Labels.AUTH_KEY), N_H);

		final var seed = expand(randomizedPassword, Arrays.concatenate(envelopeNonce, Labels.PRIVATE_KEY), N_SEED);
		final var clientKeyPair = oprf.deriveKeyPair(seed, ObjectUtils.defaultIfNull(params.customDeriveDhKeyPairLabel(), Labels.NOPAQUE_DERIVE_DH_KEYPAIR));
		final var cleartextCredentials = createCleartextCredentials(serverPublicKey, clientKeyPair.publicKey(), serverIdentity, clientIdentity);

		final var authTag = hmac(authKey, Arrays.concatenate(new byte[][]{
			envelopeNonce,
			serverPublicKey,
			I2OSP(cleartextCredentials.serverIdentity().length, 2),
			cleartextCredentials.serverIdentity(),
			I2OSP(cleartextCredentials.clientIdentity().length, 2),
			cleartextCredentials.clientIdentity()
		}));

		return new StoreResult(Arrays.concatenate(envelopeNonce, authTag), clientKeyPair.publicKey(), maskingKey, exportKey);
	}

	private RecoverResult recover(byte[] randomizedPassword, byte[] serverPublicKey, byte[] envelope, byte[] serverIdentity, byte[] clientIdentity) throws Exception {
		final var envelopeNonce = Arrays.copyOfRange(envelope, 0, N_N);
		final var authTag = Arrays.copyOfRange(envelope, N_N, envelope.length);

		final var exportKey = expand(randomizedPassword, Arrays.concatenate(envelopeNonce, Labels.EXPORT_KEY), N_H);
		final var authKey = expand(randomizedPassword, Arrays.concatenate(envelopeNonce, Labels.AUTH_KEY), N_H);

		final var seed = expand(randomizedPassword, Arrays.concatenate(envelopeNonce, Labels.PRIVATE_KEY), N_SEED);
		final var clientKeyPair = oprf.deriveKeyPair(seed, ObjectUtils.defaultIfNull(params.customDeriveDhKeyPairLabel(), Labels.NOPAQUE_DERIVE_DH_KEYPAIR));
		final var cleartextCredentials = createCleartextCredentials(serverPublicKey, clientKeyPair.publicKey(), serverIdentity, clientIdentity);

		final var expectedAuthTag = hmac(authKey, Arrays.concatenate(new byte[][]{
			envelopeNonce,
			serverPublicKey,
			I2OSP(cleartextCredentials.serverIdentity().length, 2),
			cleartextCredentials.serverIdentity(),
			I2OSP(cleartextCredentials.clientIdentity().length, 2),
			cleartextCredentials.clientIdentity()
		}));

		if (!Arrays.constantTimeAreEqual(expectedAuthTag, authTag)) {
			clearArrays(exportKey, authKey, seed, clientKeyPair.secretKey(), clientKeyPair.publicKey());
			throw new IllegalArgumentException("authentication tags do not match");
		}

		return new RecoverResult(exportKey);
	}


	/**
	 * Client - Generate a uniform random secret
	 * @return
	 */
	public byte[] randomSecret() {
		return RandomUtils.secureStrong().randomBytes(N_SEED);
	}

	/**
	 *
	 */
	public static final record CreateRegistrationRequestResult(byte[] blind, byte[] request) {}

	/**
	 * Client: First step in the NOPAQUE registration process. Uses the (uniformly random) <code>secret</code>
	 * to generate a <code>blind</code> parameter and <code>RegistrationRequest</code>, which is sent to the server.
	 *
	 * @param secret A randomly chosen secret, in the case of NOPAQUE, should be a uniform random bytestring (i.e. use <code>randomSecret()</code>)
	 * @return A <code>CreateRegistrationRequestResult</code> record, containing the <code>blind</code> parameter and the serialized <code>request</code>.
	 */
	public CreateRegistrationRequestResult createRegistrationRequest(byte[] secret) throws Exception {
		final var blindResult = oprf.blind(secret, params.blindRegistration());
		final var blindedMessage = oprf.encodeElement(blindResult.blindedElement());
		state = new ClientState(secret, oprf.encodeScalar(blindResult.blind()));
		return new CreateRegistrationRequestResult(oprf.encodeScalar(blindResult.blind()), blindedMessage);
	}

	/**
	 * Client: Result object for the <code>finalizeRegistrationRequest</code> step.
	 * Contains the <code>exportKey</code> and the serialized <code>record</code> to be
	 * sent to the server for longterm storage (completing the registration).
	 *
	 * Note that the client won't be able to recover the <code>exportKey</code> if the
	 * registration's last step (sending the record to the server for storage) is not
	 * successfully completed! (You might also want to store any server-generated
	 * <code>CredentialIdentifier</code> on the client)
	 */
	public static final record FinalizeRegistrationResult(byte[] record, byte[] exportKey) {}

	/**
	 * Client:
	 * @param response
	 * @param serverIdentity
	 * @param clientIdentity
	 * @return
	 * @throws Exception
	 */
	public FinalizeRegistrationResult finalizeRegistrationRequest(RegistrationResponse response, byte[] serverIdentity, byte[] clientIdentity) throws Exception {
		final var evaluatedElement = oprf.decodeElement(response.evaluatedMessage());
		final var oprfOutput = oprf.finalize(state.secret(), oprf.decodeScalar(state.blind()), evaluatedElement);

		final var stretchedOprfOutput = ObjectUtils.defaultIfNull(stretch, Stretcher.IDENTITY).stretch(oprfOutput);
		final var randomizedPassword = extract(Arrays.concatenate(oprfOutput, stretchedOprfOutput), ArrayUtils.EMPTY_BYTE_ARRAY);
		final var result = store(randomizedPassword, response.serverPublicKey(), serverIdentity, clientIdentity);
		return new FinalizeRegistrationResult(Arrays.concatenate(result.clientPublicKey(), result.maskingKey(), result.envelope()), result.exportKey());
	}

	/**
	 * Client: Initial step of the NOPAQUE recover process, uses the initial <code>password</code>
	 * to generate a <code>RecoverRequest</code> which is then sent to the server
	 *
	 * @param secret
	 * @return <code>RecoverRequest</code>
	 */
	public RecoverRequest createRecoverRequest(byte[] secret) throws Exception {
		final var oprfResult = oprf.blind(secret, params.blindRecover());
		final var blindedMessage = oprf.encodeElement(oprfResult.blindedElement());
		state = new ClientState(secret, oprf.encodeScalar(oprfResult.blind()));
		return new RecoverRequest(blindedMessage);
	}

	/**
	 * Client: Last step in the NOPAQUE recover process, uses the server's <code>RecoverResponse</code>
	 * to recover the <code>exportKey</code>
	 *
	 * @param ke2 <code>RecoverResponse</code> generated by the server in the previous step <code>Server::createRecoverResponse()</code>
	 * @param serverIdentity Optional server identity
	 * @param clientIdentity Optional client identity
	 * @return The recovered <code>exportKey</code>
	 * @throws Exception
	 */
	public byte[] finalizeRecoverRequest(RecoverResponse ke2, byte[] serverIdentity, byte[] clientIdentity) throws Exception {
		final var evaluatedElement = oprf.decodeElement(ke2.evaluatedMessage());
		final var oprfOutput = oprf.finalize(state.secret(), oprf.decodeScalar(state.blind()), evaluatedElement);
		final var stretchedOprfOutput = ObjectUtils.defaultIfNull(stretch, Stretcher.IDENTITY).stretch(oprfOutput);
		final var randomizedPassword = extract(Arrays.concatenate(oprfOutput, stretchedOprfOutput), ArrayUtils.EMPTY_BYTE_ARRAY);

		final var maskingKey = expand(randomizedPassword, Labels.MASKING_KEY, N_H);
		final var credentialResponsePad = expand(maskingKey, Arrays.concatenate(ke2.maskingNonce(), Labels.CREDENTIAL_RESPONSE_PAD), N_PK + N_N + N_M);

		final var unmaskedResponse = new byte[credentialResponsePad.length];
		Bytes.xor(credentialResponsePad.length, ke2.maskedResponse(), credentialResponsePad, unmaskedResponse);
		final var clientRecord = MaskedResponse.fromBytes(unmaskedResponse);

		return recover(randomizedPassword, clientRecord.serverPublicKey(), Arrays.concatenate(clientRecord.envelopeNonce(), clientRecord.authTag()),
			serverIdentity, clientIdentity).exportKey();
	}
}
