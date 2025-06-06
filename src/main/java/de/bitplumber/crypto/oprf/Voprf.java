package de.bitplumber.crypto.oprf;

import com.weavechain.curve25519.RistrettoElement;
import com.weavechain.curve25519.Scalar;

public interface Voprf<S, E, BR, BER, P> {
	public KeyPair deriveKeyPair(byte[] seed, byte[] info) throws Exception;
	public KeyPair randomKeyPair();

	public byte[] encodeElement(E element);
	public E decodeElement(byte[] input) throws Exception;

	public byte[] encodeScalar(S scalar);
	public S decodeScalar(byte[] input) throws Exception;
	public S randomScalar();

	public BR blind(byte[] input) throws Exception;
	public BER blindEvaluate(byte[] serverSecretKey, byte[] serverPublicKey, E blindedElement) throws Exception;
	public byte[] finalize(byte[] input, S blind, E evaluatedElement, E blindedElement, byte[] serverPublicKey, P proof) throws Exception;
	public byte[] evaluate(byte[] serverSecretKey, byte[] input) throws Exception;
}
