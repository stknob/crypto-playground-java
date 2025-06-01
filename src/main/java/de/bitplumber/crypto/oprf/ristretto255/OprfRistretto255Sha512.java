package de.bitplumber.crypto.oprf.ristretto255;

import java.nio.charset.StandardCharsets;

import org.bouncycastle.util.Arrays;

import com.weavechain.curve25519.RistrettoElement;
import com.weavechain.curve25519.Scalar;

import de.bitplumber.crypto.oprf.Labels;
import de.bitplumber.crypto.oprf.Modes;
import de.bitplumber.crypto.oprf.Oprf;

public class OprfRistretto255Sha512 extends AbstractRistretto255Sha512 implements Oprf<Scalar, RistrettoElement, OprfRistretto255Sha512.BlindResult> {
	public static record BlindResult(Scalar blind, RistrettoElement blindedElement) {}

	private static final byte[] CONTEXT = Arrays.concatenate(new byte[][]{
		Labels.CONTEXT_PREFIX, Modes.OPRF,
		("-" + SUITE_ID).getBytes(StandardCharsets.UTF_8),
	});

	protected byte[] context() {
		return CONTEXT;
	}

	private BlindResult doBlind(byte[] input, Scalar blind) {
		final var inputElement = hashToGroup(input, null);
		if (inputElement.equals(RistrettoElement.IDENTITY))
			throw new IllegalArgumentException("InvalidInputError");

		final var blindedElement = inputElement.multiply(blind);
		return new BlindResult(blind, blindedElement);
	}

	public BlindResult blind(byte[] input, byte[] blind) {
		return doBlind(input, blind == null ? randomScalar() : decodeScalar(blind));
	}

	public BlindResult blind(byte[] input) {
		return doBlind(input, randomScalar());
	}

	public RistrettoElement blindEvaluate(byte[] secretKey, RistrettoElement blindedElement) {
		final var skS = decodeScalar(secretKey);
		return blindedElement.multiply(skS);
	}

	public byte[] finalize(byte[] input, Scalar blind, RistrettoElement evaluatedElement) {
		final var invBlind = blind.invert();
		final var n = evaluatedElement.multiply(invBlind);
		final var unblindedElement = encodeElement(n);
		return hash(Arrays.concatenate(new byte[][]{
			I2OSP(input.length, 2), input,
			I2OSP(unblindedElement.length, 2), unblindedElement,
			Labels.FINALIZE
		}));
	}

	public byte[] evaluate(byte[] secretKey, byte[] input) {
		final var inputElement = hashToGroup(input, null);
		if (inputElement.equals(RistrettoElement.IDENTITY))
			throw new IllegalArgumentException("InvalidInputError");

		final var skS = decodeScalar(secretKey);
		final var evaluatedElement = inputElement.multiply(skS);
		final var issuedElement = encodeElement(evaluatedElement);

		return hash(Arrays.concatenate(new byte[][]{
			I2OSP(input.length, 2), input,
			I2OSP(issuedElement.length, 2), issuedElement,
			Labels.FINALIZE
		}));
	}
}
