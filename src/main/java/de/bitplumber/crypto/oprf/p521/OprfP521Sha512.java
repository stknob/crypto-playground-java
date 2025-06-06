package de.bitplumber.crypto.oprf.p521;

import java.nio.charset.StandardCharsets;

import org.bouncycastle.util.Arrays;

import de.bitplumber.crypto.oprf.Labels;
import de.bitplumber.crypto.oprf.Modes;
import de.bitplumber.crypto.oprf.Oprf;

public class OprfP521Sha512 extends AbstractP521Sha512 implements Oprf<P521FieldElement, P521GroupElement, OprfP521Sha512.BlindResult> {
	public static record BlindResult(P521FieldElement blind, P521GroupElement blindedElement) {}

	private static final byte[] CONTEXT = Arrays.concatenate(new byte[][]{
		Labels.CONTEXT_PREFIX, Modes.OPRF,
		("-" + SUITE_ID).getBytes(StandardCharsets.UTF_8),
	});

	protected byte[] context() {
		return CONTEXT;
	}

	private BlindResult doBlind(byte[] input, P521FieldElement blind) throws Exception {
		final var inputElement = hashToGroup(input, null);
		if (P521GroupElement.IDENTITY.ctEquals(inputElement))
			throw new IllegalArgumentException("InvalidInputError");

		final var blindedElement = inputElement.multiply(blind);
		return new BlindResult(blind, blindedElement);
	}

	public BlindResult blind(byte[] input, byte[] blind) throws Exception {
		return doBlind(input, blind == null ? randomScalar() : decodeScalar(blind));
	}

	public BlindResult blind(byte[] input) throws Exception {
		return doBlind(input, randomScalar());
	}

	public P521GroupElement blindEvaluate(byte[] serverSecretKey, P521GroupElement blindedElement) throws Exception {
		final var skS = decodeScalar(serverSecretKey);
		return blindedElement.multiply(skS);
	}

	public byte[] finalize(byte[] input, P521FieldElement blind, P521GroupElement evaluatedElement) throws Exception {
		final var invBlind = blind.invert();
		final var n = evaluatedElement.multiply(invBlind);
		final var unblindedElement = encodeElement(n);

		return hash(Arrays.concatenate(new byte[][]{
			I2OSP(input.length, 2), input,
			I2OSP(unblindedElement.length, 2), unblindedElement,
			Labels.FINALIZE
		}));
	}

	public byte[] evaluate(byte[] serverSecretKey, byte[] input) throws Exception {
		final var inputElement = hashToGroup(input, null);
		if (P521GroupElement.IDENTITY.ctEquals(inputElement))
			throw new IllegalArgumentException("InvalidInputError");

		final var skS = decodeScalar(serverSecretKey);
		final var evaluatedElement = inputElement.multiply(skS);
		final var issuedElement = encodeElement(evaluatedElement);

		return hash(Arrays.concatenate(new byte[][]{
			I2OSP(input.length, 2), input,
			I2OSP(issuedElement.length, 2), issuedElement,
			Labels.FINALIZE
		}));
	}
}
