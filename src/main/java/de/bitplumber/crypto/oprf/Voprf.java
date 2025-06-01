package de.bitplumber.crypto.oprf;

import com.weavechain.curve25519.RistrettoElement;
import com.weavechain.curve25519.Scalar;

public interface Voprf<S, E, BR, BER, P> {
	public KeyPair deriveKeypair(byte[] seed, byte[] info) throws Exception;
	public KeyPair randomKeypair();

	public byte[] encodeElement(E element);
	public E decodeElement(byte[] input) throws Exception;

	public byte[] encodeScalar(S scalar);
	public S decodeScalar(byte[] input);
	public S randomScalar();

	public BR blind(byte[] input);
	public BER blindEvaluate(byte[] secretKey, byte[] publicKey, RistrettoElement blindedElement) throws Exception;
	public byte[] finalize(byte[] input, Scalar blind, RistrettoElement evaluatedElement, RistrettoElement blindedElement, byte[] publicKey, P proof) throws Exception;
	public byte[] evaluate(byte[] secretKey, byte[] input);
}
