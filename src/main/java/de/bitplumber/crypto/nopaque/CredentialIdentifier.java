package de.bitplumber.crypto.nopaque;

public class CredentialIdentifier {
	private final byte[] identifier;

	private CredentialIdentifier(byte[] input) {
		this.identifier = input;
	}

	public static CredentialIdentifier fromBytes(byte[] input) {
		return new CredentialIdentifier(input);
	}

	public byte[] toByteArray() {
		return this.identifier;
	}
}
