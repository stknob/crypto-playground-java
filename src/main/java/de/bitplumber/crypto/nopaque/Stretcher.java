package de.bitplumber.crypto.nopaque;

public interface Stretcher {
	public static final Stretcher IDENTITY = input ->  input;
	public byte[] stretch(byte[] input);
}
