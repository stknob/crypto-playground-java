package de.bitplumber.crypto.nopaque.ristretto255;

import java.math.BigInteger;

import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

import de.bitplumber.crypto.oprf.ristretto255.Ristretto255Oprf;

/**
 * Abstract base class for NOPAQUE Ristretto255-SHA512 suite, including
 * all parameters, shared methods and data structures shared between client
 * and server
 */
public abstract class AbstractRistretto255 {
	protected static final Ristretto255Oprf oprf = new Ristretto255Oprf();

	protected static final int N_SEED = 32; // Seed size
	protected static final int N_OE = 32;   // OPRF element size
	protected static final int N_OK = 32;   // OPRF secret key size
	protected static final int N_PK = 32;   // Public key size
	protected static final int N_SK = 32;   // Secret key size
	protected static final int N_H = 64;    // Hash output size (SHA512)
	protected static final int N_N = 32;    // Nonce size
	protected static final int N_M = 64;    // MAC size

	/**
	 * HKDF-SHA512-Expand - Implements the expand step of HKDF with SHA512,
	 * as used by the NOPAQUE algorithm over Ristretto255
	 *
	 * @param prk
	 * @param info
	 * @param length
	 * @return
	 */
	protected byte[] expand(byte[] prk, byte[] info, int length) {
		final var h = new HKDFBytesGenerator(new SHA512Digest());
		h.init(HKDFParameters.skipExtractParameters(prk, info));

		final var out = new byte[length];
		h.generateBytes(out, 0, out.length);
		return out;
	}

	/**
	 * HKDF-SHA512-Extract - Implements the extract step of HKDF with SHA512,
	 * as used by the NOPAQUE algorithm over Ristretto255
	 *
	 * @param ikm
	 * @param salt
	 * @return
	 */
	protected byte[] extract(byte[] ikm, byte[] salt) {
		return new HKDFBytesGenerator(new SHA512Digest())
			.extractPRK(salt, ikm);
	}

	/**
	 * HMAC-SHA512 - Calculates a message authentication code (MAC) using HMAC with SHA512,
	 * as used by the NOPAQUE algorithm over Ristretto255
	 * @param key
	 * @param msg
	 * @return
	 */
	protected byte[] hmac(byte[] key, byte[] msg) {
		final var h = new HMac(new SHA512Digest());
		h.init(new KeyParameter(key));
		h.update(msg, 0, msg.length);

		final var out = new byte[h.getMacSize()];
		h.doFinal(out, 0);
		return out;
	}

	/**
	 * I2OSP - Serialize a given <code>value</code> into an unsigned big-endian
	 * encoded byte string of fixed <code>size</code>.
	 *
	 * @param value Value to serialize
	 * @param size Number of bytes to pack the value into
	 * @return The encoded big-endian byte string
	 */
	protected byte[] I2OSP(long value, int size) {
		return BigIntegers.asUnsignedByteArray(size, BigInteger.valueOf(value));
	}

	/**
	 * Client -> Server:
	 */
	public static final record RegistrationRequest(byte[] blindedElement) {
		public static RegistrationRequest fromBytes(byte[] input) {
			return new RegistrationRequest(input);
		}

		public byte[] toByteArray() {
			return blindedElement;
		}
	}


	/**
	 * Server -> Client:
	 */
	public static final record RegistrationResponse(byte[] evaluatedMessage, byte[] serverPublicKey) {
		public static RegistrationResponse fromBytes(byte[] input) {
			final var evaluatedMessage = Arrays.copyOfRange(input, 0, N_OE);
			final var serverPublicKey = Arrays.copyOfRange(input, N_OE, input.length);
			return new RegistrationResponse(evaluatedMessage, serverPublicKey);
		}

		public byte[] toByteArray() {
			return Arrays.concatenate(evaluatedMessage, serverPublicKey);
		}
	}


	/**
	 * Client -> Server:
	 */
	public static final record RecoverRequest(byte[] blindedMessage) {
		public static RecoverRequest fromBytes(byte[] input) {
			final var blindedMessage = Arrays.copyOfRange(input, 0, N_H);
			return new RecoverRequest(blindedMessage);
		}

		public byte[] toByteArray() {
			return blindedMessage;
		}
	}

	/**
	 * Client/Server: Masked response object sent by the server, used to decode the contents after unmasking
	 */
	protected static final record MaskedResponse(byte[] serverPublicKey, byte[] envelopeNonce, byte[] authTag) {
		public static MaskedResponse fromBytes(byte[] input) {
			final var serverPublicKey = Arrays.copyOfRange(input, 0, N_PK);
			final var envelopeNonce = Arrays.copyOfRange(input, N_PK, N_PK + N_N);
			final var authTag = Arrays.copyOfRange(input, N_PK + N_N, input.length);
			return new MaskedResponse(serverPublicKey, envelopeNonce, authTag);
		}

		public byte[] toByteArray() {
			return Arrays.concatenate(serverPublicKey, envelopeNonce, authTag);
		}
	}

	/**
	 * Server -> Client:
	 */
	public static final record RecoverResponse(byte[] evaluatedMessage, byte[] maskingNonce, byte[] maskedResponse) {
		public static RecoverResponse fromBytes(byte[] input) {
			final var evaluatedMessage = Arrays.copyOfRange(input, 0, N_OE);
			final var maskingNonce = Arrays.copyOfRange(input, N_OE, N_OE + N_N);
			final var maskedResponse = Arrays.copyOfRange(input, N_OE + N_N, input.length);
			return new RecoverResponse(evaluatedMessage, maskingNonce, maskedResponse);
		}

		public byte[] toByteArray() {
			return Arrays.concatenate(evaluatedMessage, maskingNonce, maskedResponse);
		}
	}
}
