package de.bitplumber.crypto.oprf;

public abstract class Modes {
	public static final byte[] OPRF  = new byte[]{ 0x00 };
	public static final byte[] VOPRF = new byte[]{ 0x01 };
	public static final byte[] POPRF = new byte[]{ 0x02 };
}
