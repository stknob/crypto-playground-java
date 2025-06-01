package de.bitplumber.crypto.oprf;

import java.nio.charset.StandardCharsets;

public abstract class Labels {
	public static final byte[] CONTEXT_PREFIX = "OPRFV1-".getBytes(StandardCharsets.UTF_8);
	public static final byte[] DERIVE_KEYPAIR = "DeriveKeyPair".getBytes(StandardCharsets.UTF_8);
	public static final byte[] FINALIZE = "Finalize".getBytes(StandardCharsets.UTF_8);
	public static final byte[] HASH_TO_SCALAR = "HashToScalar-".getBytes(StandardCharsets.UTF_8);
	public static final byte[] HASH_TO_GROUP = "HashToGroup-".getBytes(StandardCharsets.UTF_8);
	public static final byte[] CHALLENGE = "Challenge".getBytes(StandardCharsets.UTF_8);
	public static final byte[] COMPOSITE = "Composite".getBytes(StandardCharsets.UTF_8);
	public static final byte[] SEED_DST_PREFIX = "Seed-".getBytes(StandardCharsets.UTF_8);
	public static final byte[] INFO = "Info".getBytes(StandardCharsets.UTF_8);

	private Labels() { /*  */ }
}
