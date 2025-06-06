package de.bitplumber.crypto.oprf;

import java.nio.charset.StandardCharsets;

import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;

public class ECCurveOprf implements Oprf<ECFieldElement, ECPoint, ECCurveOprf.BlindResult> {
	public static record BlindResult(ECFieldElement blind, ECPoint blindedElement) {}

	private final ECCurveSuite suite;
	private final byte[] context;

	private ECCurveOprf(final ECCurveSuite suite) {
		this.suite = suite;
		this.context = Arrays.concatenate(new byte[][]{
			Labels.CONTEXT_PREFIX, Modes.OPRF,
			("-" + suite.getName()).getBytes(StandardCharsets.UTF_8),
		});
	}

	public static ECCurveOprf createP256() {
		return new ECCurveOprf(ECCurveSuite.createP256());
	}

	public static ECCurveOprf createP384() {
		return new ECCurveOprf(ECCurveSuite.createP384());
	}

	public static ECCurveOprf createP521() {
		return new ECCurveOprf(ECCurveSuite.createP521());
	}

	public KeyPair randomKeyPair() {
		return suite.randomKeyPair();
	}

	public KeyPair deriveKeyPair(byte[] seed, byte[] info) throws Exception {
		return suite.deriveKeyPair(seed, info, context);
	}

	public byte[] encodeElement(ECPoint element) {
		return suite.encodeElement(element);
	}

	public ECPoint decodeElement(byte[] encoded) {
		return suite.decodeElement(encoded);
	}

	public ECFieldElement randomScalar() {
		return suite.randomScalar();
	}

	public byte[] encodeScalar(ECFieldElement scalar) {
		return suite.encodeScalar(scalar);
	}

	public ECFieldElement decodeScalar(byte[] encoded) {
		return suite.decodeScalar(encoded);
	}

	private BlindResult doBlind(byte[] input, ECFieldElement blind) throws Exception {
		final var inputElement = suite.hashToGroup(input, null, context);
		if (inputElement.isInfinity() || !inputElement.isValid())
			throw new IllegalArgumentException("InvalidInputError");

		final var blindedElement = inputElement.multiply(blind.toBigInteger());
		return new BlindResult(blind, blindedElement);
	}

	protected BlindResult blind(byte[] input, byte[] blind) throws Exception {
		return doBlind(input, blind == null ? suite.randomScalar() : suite.decodeScalar(blind));
	}

	public BlindResult blind(byte[] input) throws Exception {
		return doBlind(input, suite.randomScalar());
	}

	public ECPoint blindEvaluate(byte[] serverSecretKey, ECPoint blindedElement) throws Exception {
		final var skS = suite.decodeScalar(serverSecretKey);
		return blindedElement.multiply(skS.toBigInteger());
	}

	public byte[] finalize(byte[] input, ECFieldElement blind, ECPoint evaluatedElement) throws Exception {
		final var invBlind = suite.invertScalar(blind);
		final var n = evaluatedElement.multiply(invBlind.toBigInteger());
		final var unblindedElement = suite.encodeElement(n);

		return suite.hash(Arrays.concatenate(new byte[][]{
			suite.I2OSP(input.length, 2), input,
			suite.I2OSP(unblindedElement.length, 2), unblindedElement,
			Labels.FINALIZE
		}));
	}

	public byte[] evaluate(byte[] serverSecretKey, byte[] input) throws Exception {
		final var inputElement = suite.hashToGroup(input, null, context);
		if (inputElement.isInfinity() || !inputElement.isValid())
			throw new IllegalArgumentException("InvalidInputError");

		final var skS = suite.decodeScalar(serverSecretKey);
		final var evaluatedElement = inputElement.multiply(skS.toBigInteger());
		final var issuedElement = suite.encodeElement(evaluatedElement);

		return suite.hash(Arrays.concatenate(new byte[][]{
			suite.I2OSP(input.length, 2), input,
			suite.I2OSP(issuedElement.length, 2), issuedElement,
			Labels.FINALIZE
		}));
	}
}
