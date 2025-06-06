package de.bitplumber.crypto.h2c;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;

import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

public class ECCurveHasherTest {
	public static final record RFC9830TestVector(String DST, String msg, byte[][] u, byte[] px, byte[] py) {}
	/**
	 *  RFC9830 - J1.1 - P256_XMD:SHA-256_SSWU_RO_
	 */
	public static final RFC9830TestVector[] P256HashToCurveTestVectors = new RFC9830TestVector[]{
		new RFC9830TestVector(
			"QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_",
			"",
			new byte[][]{
				Hex.decode("ad5342c66a6dd0ff080df1da0ea1c04b96e0330dd89406465eeba11582515009"),
				Hex.decode("8c0f1d43204bd6f6ea70ae8013070a1518b43873bcd850aafa0a9e220e2eea5a"),
			},
			Hex.decode("2c15230b26dbc6fc9a37051158c95b79656e17a1a920b11394ca91c44247d3e4"),
			Hex.decode("8a7a74985cc5c776cdfe4b1f19884970453912e9d31528c060be9ab5c43e8415")
		),
		new RFC9830TestVector(
			"QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_",
			"abc",
			new byte[][]{
				Hex.decode("afe47f2ea2b10465cc26ac403194dfb68b7f5ee865cda61e9f3e07a537220af1"),
				Hex.decode("379a27833b0bfe6f7bdca08e1e83c760bf9a338ab335542704edcd69ce9e46e0"),
			},
			Hex.decode("0bb8b87485551aa43ed54f009230450b492fead5f1cc91658775dac4a3388a0f"),
			Hex.decode("5c41b3d0731a27a7b14bc0bf0ccded2d8751f83493404c84a88e71ffd424212e")
		),
		new RFC9830TestVector(
			"QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_",
			"abcdef0123456789",
			new byte[][]{
				Hex.decode("0fad9d125a9477d55cf9357105b0eb3a5c4259809bf87180aa01d651f53d312c"),
				Hex.decode("b68597377392cd3419d8fcc7d7660948c8403b19ea78bbca4b133c9d2196c0fb"),
			},
			Hex.decode("65038ac8f2b1def042a5df0b33b1f4eca6bff7cb0f9c6c1526811864e544ed80"),
			Hex.decode("cad44d40a656e7aff4002a8de287abc8ae0482b5ae825822bb870d6df9b56ca3")
		),
		new RFC9830TestVector(
			"QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_",
			"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
			new byte[][]{
				Hex.decode("3bbc30446f39a7befad080f4d5f32ed116b9534626993d2cc5033f6f8d805919"),
				Hex.decode("76bb02db019ca9d3c1e02f0c17f8baf617bbdae5c393a81d9ce11e3be1bf1d33"),
			},
			Hex.decode("4be61ee205094282ba8a2042bcb48d88dfbb609301c49aa8b078533dc65a0b5d"),
			Hex.decode("98f8df449a072c4721d241a3b1236d3caccba603f916ca680f4539d2bfb3c29e")
		),
		new RFC9830TestVector(
			"QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_",
			"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			new byte[][]{
				Hex.decode("4ebc95a6e839b1ae3c63b847798e85cb3c12d3817ec6ebc10af6ee51adb29fec"),
				Hex.decode("4e21af88e22ea80156aff790750121035b3eefaa96b425a8716e0d20b4e269ee"),
			},
			Hex.decode("457ae2981f70ca85d8e24c308b14db22f3e3862c5ea0f652ca38b5e49cd64bc5"),
			Hex.decode("ecb9f0eadc9aeed232dabc53235368c1394c78de05dd96893eefa62b0f4757dc")
		),
	};

	/**
	 *  RFC9830 - J1.2 - P256_XMD:SHA-256_SSWU_NU_
	 */
	public static final RFC9830TestVector[] P256EncodeToCurveTestVectors = new RFC9830TestVector[]{
		new RFC9830TestVector(
			"QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_NU_",
			"",
			new byte[][]{
				Hex.decode("b22d487045f80e9edcb0ecc8d4bf77833e2bf1f3a54004d7df1d57f4802d311f"),
			},
			Hex.decode("f871caad25ea3b59c16cf87c1894902f7e7b2c822c3d3f73596c5ace8ddd14d1"),
			Hex.decode("87b9ae23335bee057b99bac1e68588b18b5691af476234b8971bc4f011ddc99b")
		),
		new RFC9830TestVector(
			"QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_NU_",
			"abc",
			new byte[][]{
				Hex.decode("c7f96eadac763e176629b09ed0c11992225b3a5ae99479760601cbd69c221e58"),
			},
			Hex.decode("fc3f5d734e8dce41ddac49f47dd2b8a57257522a865c124ed02b92b5237befa4"),
			Hex.decode("fe4d197ecf5a62645b9690599e1d80e82c500b22ac705a0b421fac7b47157866")
		),
		new RFC9830TestVector(
			"QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_NU_",
			"abcdef0123456789",
			new byte[][]{
				Hex.decode("314e8585fa92068b3ea2c3bab452d4257b38be1c097d58a21890456c2929614d"),
			},
			Hex.decode("f164c6674a02207e414c257ce759d35eddc7f55be6d7f415e2cc177e5d8faa84"),
			Hex.decode("3aa274881d30db70485368c0467e97da0e73c18c1d00f34775d012b6fcee7f97")
		),
		new RFC9830TestVector(
			"QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_NU_",
			"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
			new byte[][]{
				Hex.decode("752d8eaa38cd785a799a31d63d99c2ae4261823b4a367b133b2c6627f48858ab"),
			},
			Hex.decode("324532006312be4f162614076460315f7a54a6f85544da773dc659aca0311853"),
			Hex.decode("8d8197374bcd52de2acfefc8a54fe2c8d8bebd2a39f16be9b710e4b1af6ef883")
		),
		new RFC9830TestVector(
			"QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_NU_",
			"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			new byte[][]{
				Hex.decode("0e1527840b9df2dfbef966678ff167140f2b27c4dccd884c25014dce0e41dfa3"),
			},
			Hex.decode("5c4bad52f81f39c8e8de1260e9a06d72b8b00a0829a8ea004a610b0691bea5d9"),
			Hex.decode("c801e7c0782af1f74f24fc385a8555da0582032a3ce038de637ccdcb16f7ef7b")
		),
	};

	public static final RFC9830TestVector[] P384HashToCurveTestVectors = new RFC9830TestVector[]{
		new RFC9830TestVector(
			"QUUX-V01-CS02-with-P384_XMD:SHA-384_SSWU_RO_",
			"",
			new byte[][]{
				Hex.decode("25c8d7dc1acd4ee617766693f7f8829396065d1b447eedb155871feffd9c6653279ac7e5c46edb7010a0e4ff64c9f3b4"),
				Hex.decode("59428be4ed69131df59a0c6a8e188d2d4ece3f1b2a3a02602962b47efa4d7905945b1e2cc80b36aa35c99451073521ac"),
			},
			Hex.decode("eb9fe1b4f4e14e7140803c1d99d0a93cd823d2b024040f9c067a8eca1f5a2eeac9ad604973527a356f3fa3aeff0e4d83"),
			Hex.decode("0c21708cff382b7f4643c07b105c2eaec2cead93a917d825601e63c8f21f6abd9abc22c93c2bed6f235954b25048bb1a")
		),
		new RFC9830TestVector(
			"QUUX-V01-CS02-with-P384_XMD:SHA-384_SSWU_RO_",
			"abc",
			new byte[][]{
				Hex.decode("53350214cb6bef0b51abb791b1c4209a2b4c16a0c67e1ab1401017fad774cd3b3f9a8bcdf7f6229dd8dd5a075cb149a0"),
				Hex.decode("c0473083898f63e03f26f14877a2407bd60c75ad491e7d26cbc6cc5ce815654075ec6b6898c7a41d74ceaf720a10c02e"),
			},
			Hex.decode("e02fc1a5f44a7519419dd314e29863f30df55a514da2d655775a81d413003c4d4e7fd59af0826dfaad4200ac6f60abe1"),
			Hex.decode("01f638d04d98677d65bef99aef1a12a70a4cbb9270ec55248c04530d8bc1f8f90f8a6a859a7c1f1ddccedf8f96d675f6")
		),
		new RFC9830TestVector(
			"QUUX-V01-CS02-with-P384_XMD:SHA-384_SSWU_RO_",
			"abcdef0123456789",
			new byte[][]{
				Hex.decode("aab7fb87238cf6b2ab56cdcca7e028959bb2ea599d34f68484139dde85ec6548a6e48771d17956421bdb7790598ea52e"),
				Hex.decode("26e8d833552d7844d167833ca5a87c35bcfaa5a0d86023479fb28e5cd6075c18b168bf1f5d2a0ea146d057971336d8d1"),
			},
			Hex.decode("bdecc1c1d870624965f19505be50459d363c71a699a496ab672f9a5d6b78676400926fbceee6fcd1780fe86e62b2aa89"),
			Hex.decode("57cf1f99b5ee00f3c201139b3bfe4dd30a653193778d89a0accc5e0f47e46e4e4b85a0595da29c9494c1814acafe183c")
		),
		new RFC9830TestVector(
			"QUUX-V01-CS02-with-P384_XMD:SHA-384_SSWU_RO_",
			"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
			new byte[][]{
				Hex.decode("04c00051b0de6e726d228c85bf243bf5f4789efb512b22b498cde3821db9da667199b74bd5a09a79583c6d353a3bb41c"),
				Hex.decode("97580f218255f899f9204db64cd15e6a312cb4d8182375d1e5157c8f80f41d6a1a4b77fb1ded9dce56c32058b8d5202b"),
			},
			Hex.decode("03c3a9f401b78c6c36a52f07eeee0ec1289f178adf78448f43a3850e0456f5dd7f7633dd31676d990eda32882ab486c0"),
			Hex.decode("cc183d0d7bdfd0a3af05f50e16a3f2de4abbc523215bf57c848d5ea662482b8c1f43dc453a93b94a8026db58f3f5d878")
		),
		new RFC9830TestVector(
			"QUUX-V01-CS02-with-P384_XMD:SHA-384_SSWU_RO_",
			"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			new byte[][]{
				Hex.decode("480cb3ac2c389db7f9dac9c396d2647ae946db844598971c26d1afd53912a1491199c0a5902811e4b809c26fcd37a014"),
				Hex.decode("d28435eb34680e148bf3908536e42231cba9e1f73ae2c6902a222a89db5c49c97db2f8fa4d4cd6e424b17ac60bdb9bb6"),
			},
			Hex.decode("7b18d210b1f090ac701f65f606f6ca18fb8d081e3bc6cbd937c5604325f1cdea4c15c10a54ef303aabf2ea58bd9947a4"),
			Hex.decode("ea857285a33abb516732915c353c75c576bf82ccc96adb63c094dde580021eddeafd91f8c0bfee6f636528f3d0c47fd2")
		),
	};

	public static final RFC9830TestVector[] P384EncodeToCurveTestVectors = new RFC9830TestVector[]{
		new RFC9830TestVector(
			"QUUX-V01-CS02-with-P384_XMD:SHA-384_SSWU_NU_",
			"",
			new byte[][]{
				Hex.decode("bc7dc1b2cdc5d588a66de3276b0f24310d4aca4977efda7d6272e1be25187b001493d267dc53b56183c9e28282368e60"),
			},
			Hex.decode("de5a893c83061b2d7ce6a0d8b049f0326f2ada4b966dc7e72927256b033ef61058029a3bfb13c1c7ececd6641881ae20"),
			Hex.decode("63f46da6139785674da315c1947e06e9a0867f5608cf24724eb3793a1f5b3809ee28eb21a0c64be3be169afc6cdb38ca")
		),
		new RFC9830TestVector(
			"QUUX-V01-CS02-with-P384_XMD:SHA-384_SSWU_NU_",
			"abc",
			new byte[][]{
				Hex.decode("9de6cf41e6e41c03e4a7784ac5c885b4d1e49d6de390b3cdd5a1ac5dd8c40afb3dfd7bb2686923bab644134483fc1926"),
			},
			Hex.decode("1f08108b87e703c86c872ab3eb198a19f2b708237ac4be53d7929fb4bd5194583f40d052f32df66afe5249c9915d139b"),
			Hex.decode("1369dc8d5bf038032336b989994874a2270adadb67a7fcc32f0f8824bc5118613f0ac8de04a1041d90ff8a5ad555f96c")
		),
		new RFC9830TestVector(
			"QUUX-V01-CS02-with-P384_XMD:SHA-384_SSWU_NU_",
			"abcdef0123456789",
			new byte[][]{
				Hex.decode("84e2d430a5e2543573e58e368af41821ca3ccc97baba7e9aab51a84543d5a0298638a22ceee6090d9d642921112af5b7"),
			},
			Hex.decode("4dac31ec8a82ee3c02ba2d7c9fa431f1e59ffe65bf977b948c59e1d813c2d7963c7be81aa6db39e78ff315a10115c0d0"),
			Hex.decode("845333cdb5702ad5c525e603f302904d6fc84879f0ef2ee2014a6b13edd39131bfd66f7bd7cdc2d9ccf778f0c8892c3f")
		),
		new RFC9830TestVector(
			"QUUX-V01-CS02-with-P384_XMD:SHA-384_SSWU_NU_",
			"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
			new byte[][]{
				Hex.decode("504e4d5a529333b9205acaa283107bd1bffde753898f7744161f7dd19ba57fbb6a64214a2e00ddd2613d76cd508ddb30"),
			},
			Hex.decode("13c1f8c52a492183f7c28e379b0475486718a7e3ac1dfef39283b9ce5fb02b73f70c6c1f3dfe0c286b03e2af1af12d1d"),
			Hex.decode("57e101887e73e40eab8963324ed16c177d55eb89f804ec9df06801579820420b5546b579008df2145fd770f584a1a54c")
		),
		new RFC9830TestVector(
			"QUUX-V01-CS02-with-P384_XMD:SHA-384_SSWU_NU_",
			"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			new byte[][]{
				Hex.decode("7b01ce9b8c5a60d9fbc202d6dde92822e46915d8c17e03fcb92ece1ed6074d01e149fc9236def40d673de903c1d4c166"),
			},
			Hex.decode("af129727a4207a8cb9e9dce656d88f79fce25edbcea350499d65e9bf1204537bdde73c7cefb752a6ed5ebcd44e183302"),
			Hex.decode("ce68a3d5e161b2e6a968e4ddaa9e51504ad1516ec170c7eef3ca6b5327943eca95d90b23b009ba45f58b72906f2a99e2")
		),
	};

	public static final RFC9830TestVector[] P521HashToCurveTestVectors = new RFC9830TestVector[]{
		new RFC9830TestVector(
			"QUUX-V01-CS02-with-P521_XMD:SHA-512_SSWU_RO_",
			"",
			new byte[][]{
				Hex.decode("01e5f09974e5724f25286763f00ce76238c7a6e03dc396600350ee2c4135fb17dc555be99a4a4bae0fd303d4f66d984ed7b6a3ba386093752a855d26d559d69e7e9e"),
				Hex.decode("00ae593b42ca2ef93ac488e9e09a5fe5a2f6fb330d18913734ff602f2a761fcaaf5f596e790bcc572c9140ec03f6cccc38f767f1c1975a0b4d70b392d95a0c7278aa"),
			},
			Hex.decode("00fd767cebb2452030358d0e9cf907f525f50920c8f607889a6a35680727f64f4d66b161fafeb2654bea0d35086bec0a10b30b14adef3556ed9f7f1bc23cecc9c088"),
			Hex.decode("0169ba78d8d851e930680322596e39c78f4fe31b97e57629ef6460ddd68f8763fd7bd767a4e94a80d3d21a3c2ee98347e024fc73ee1c27166dc3fe5eeef782be411d")
		),
		new RFC9830TestVector(
			"QUUX-V01-CS02-with-P521_XMD:SHA-512_SSWU_RO_",
			"abc",
			new byte[][]{
				Hex.decode("003d00c37e95f19f358adeeaa47288ec39998039c3256e13c2a4c00a7cb61a34c8969472960150a27276f2390eb5e53e47ab193351c2d2d9f164a85c6a5696d94fe8"),
				Hex.decode("01f3cbd3df3893a45a2f1fecdac4d525eb16f345b03e2820d69bc580f5cbe9cb89196fdf720ef933c4c0361fcfe29940fd0db0a5da6bafb0bee8876b589c41365f15"),
			},
			Hex.decode("002f89a1677b28054b50d15e1f81ed6669b5a2158211118ebdef8a6efc77f8ccaa528f698214e4340155abc1fa08f8f613ef14a043717503d57e267d57155cf784a4"),
			Hex.decode("010e0be5dc8e753da8ce51091908b72396d3deed14ae166f66d8ebf0a4e7059ead169ea4bead0232e9b700dd380b316e9361cfdba55a08c73545563a80966ecbb86d")
		),
		new RFC9830TestVector(
			"QUUX-V01-CS02-with-P521_XMD:SHA-512_SSWU_RO_",
			"abcdef0123456789",
			new byte[][]{
				Hex.decode("00183ee1a9bbdc37181b09ec336bcaa34095f91ef14b66b1485c166720523dfb81d5c470d44afcb52a87b704dbc5c9bc9d0ef524dec29884a4795f55c1359945baf3"),
				Hex.decode("00504064fd137f06c81a7cf0f84aa7e92b6b3d56c2368f0a08f44776aa8930480da1582d01d7f52df31dca35ee0a7876500ece3d8fe0293cd285f790c9881c998d5e"),
			},
			Hex.decode("006e200e276a4a81760099677814d7f8794a4a5f3658442de63c18d2244dcc957c645e94cb0754f95fcf103b2aeaf94411847c24187b89fb7462ad3679066337cbc4"),
			Hex.decode("001dd8dfa9775b60b1614f6f169089d8140d4b3e4012949b52f98db2deff3e1d97bf73a1fa4d437d1dcdf39b6360cc518d8ebcc0f899018206fded7617b654f6b168")
		),
		new RFC9830TestVector(
			"QUUX-V01-CS02-with-P521_XMD:SHA-512_SSWU_RO_",
			"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
			new byte[][]{
				Hex.decode("0159871e222689aad7694dc4c3480a49807b1eedd9c8cb4ae1b219d5ba51655ea5b38e2e4f56b36bf3e3da44a7b139849d28f598c816fe1bc7ed15893b22f63363c3"),
				Hex.decode("004ef0cffd475152f3858c0a8ccbdf7902d8261da92744e98df9b7fadb0a5502f29c5086e76e2cf498f47321434a40b1504911552ce44ad7356a04e08729ad9411f5"),
			},
			Hex.decode("01b264a630bd6555be537b000b99a06761a9325c53322b65bdc41bf196711f9708d58d34b3b90faf12640c27b91c70a507998e55940648caa8e71098bf2bc8d24664"),
			Hex.decode("01ea9f445bee198b3ee4c812dcf7b0f91e0881f0251aab272a12201fd89b1a95733fd2a699c162b639e9acdcc54fdc2f6536129b6beb0432be01aa8da02df5e59aaa")
		),
		new RFC9830TestVector(
			"QUUX-V01-CS02-with-P521_XMD:SHA-512_SSWU_RO_",
			"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			new byte[][]{
				Hex.decode("0033d06d17bc3b9a3efc081a05d65805a14a3050a0dd4dfb4884618eb5c73980a59c5a246b18f58ad022dd3630faa22889fbb8ba1593466515e6ab4aeb7381c26334"),
				Hex.decode("0092290ab99c3fea1a5b8fb2ca49f859994a04faee3301cefab312d34227f6a2d0c3322cf76861c6a3683bdaa2dd2a6daa5d6906c663e065338b2344d20e313f1114"),
			},
			Hex.decode("00c12bc3e28db07b6b4d2a2b1167ab9e26fc2fa85c7b0498a17b0347edf52392856d7e28b8fa7a2dd004611159505835b687ecf1a764857e27e9745848c436ef3925"),
			Hex.decode("01cd287df9a50c22a9231beb452346720bb163344a41c5f5a24e8335b6ccc595fd436aea89737b1281aecb411eb835f0b939073fdd1dd4d5a2492e91ef4a3c55bcbd")
		),
	};

	public static final RFC9830TestVector[] P521EncodeToCurveTestVectors = new RFC9830TestVector[]{
		new RFC9830TestVector(
			"QUUX-V01-CS02-with-P521_XMD:SHA-512_SSWU_NU_",
			"",
			new byte[][]{
				Hex.decode("01e4947fe62a4e47792cee2798912f672fff820b2556282d9843b4b465940d7683a986f93ccb0e9a191fbc09a6e770a564490d2a4ae51b287ca39f69c3d910ba6a4f"),
			},
			Hex.decode("01ec604b4e1e3e4c7449b7a41e366e876655538acf51fd40d08b97be066f7d020634e906b1b6942f9174b417027c953d75fb6ec64b8cee2a3672d4f1987d13974705"),
			Hex.decode("00944fc439b4aad2463e5c9cfa0b0707af3c9a42e37c5a57bb4ecd12fef9fb21508568aedcdd8d2490472df4bbafd79081c81e99f4da3286eddf19be47e9c4cf0e91")
		),
		new RFC9830TestVector(
			"QUUX-V01-CS02-with-P521_XMD:SHA-512_SSWU_NU_",
			"abc",
			new byte[][]{
				Hex.decode("0019b85ef78596efc84783d42799e80d787591fe7432dee1d9fa2b7651891321be732ddf653fa8fefa34d86fb728db569d36b5b6ed3983945854b2fc2dc6a75aa25b"),
			},
			Hex.decode("00c720ab56aa5a7a4c07a7732a0a4e1b909e32d063ae1b58db5f0eb5e09f08a9884bff55a2bef4668f715788e692c18c1915cd034a6b998311fcf46924ce66a2be9a"),
			Hex.decode("003570e87f91a4f3c7a56be2cb2a078ffc153862a53d5e03e5dad5bccc6c529b8bab0b7dbb157499e1949e4edab21cf5d10b782bc1e945e13d7421ad8121dbc72b1d")
		),
		new RFC9830TestVector(
			"QUUX-V01-CS02-with-P521_XMD:SHA-512_SSWU_NU_",
			"abcdef0123456789",
			new byte[][]{
				Hex.decode("01dba0d7fa26a562ee8a9014ebc2cca4d66fd9de036176aca8fc11ef254cd1bc208847ab7701dbca7af328b3f601b11a1737a899575a5c14f4dca5aaca45e9935e07"),
			},
			Hex.decode("00bcaf32a968ff7971b3bbd9ce8edfbee1309e2019d7ff373c38387a782b005dce6ceffccfeda5c6511c8f7f312f343f3a891029c5858f45ee0bf370aba25fc990cc"),
			Hex.decode("00923517e767532d82cb8a0b59705eec2b7779ce05f9181c7d5d5e25694ef8ebd4696343f0bc27006834d2517215ecf79482a84111f50c1bae25044fe1dd77744bbd")
		),
		new RFC9830TestVector(
			"QUUX-V01-CS02-with-P521_XMD:SHA-512_SSWU_NU_",
			"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
			new byte[][]{
				Hex.decode("00844da980675e1244cb209dcf3ea0aabec23bd54b2cda69fff86eb3acc318bf3d01bae96e9cd6f4c5ceb5539df9a7ad7fcc5e9d54696081ba9782f3a0f6d14987e3"),
			},
			Hex.decode("001ac69014869b6c4ad7aa8c443c255439d36b0e48a0f57b03d6fe9c40a66b4e2eaed2a93390679a5cc44b3a91862b34b673f0e92c83187da02bf3db967d867ce748"),
			Hex.decode("00d5603d530e4d62b30fccfa1d90c2206654d74291c1db1c25b86a051ee3fffc294e5d56f2e776853406bd09206c63d40f37ad8829524cf89ad70b5d6e0b4a3b7341")
		),
		new RFC9830TestVector(
			"QUUX-V01-CS02-with-P521_XMD:SHA-512_SSWU_NU_",
			"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			new byte[][]{
				Hex.decode("01aab1fb7e5cd44ba4d9f32353a383cb1bb9eb763ed40b32bdd5f666988970205998c0e44af6e2b5f6f8e48e969b3f649cae3c6ab463e1b274d968d91c02f00cce91"),
			},
			Hex.decode("01801de044c517a80443d2bd4f503a9e6866750d2f94a22970f62d721f96e4310e4a828206d9cdeaa8f2d476705cc3bbc490a6165c687668f15ec178a17e3d27349b"),
			Hex.decode("0068889ea2e1442245fe42bfda9e58266828c0263119f35a61631a3358330f3bb84443fcb54fcd53a1d097fccbe310489b74ee143fc2938959a83a1f7dd4a6fd395b")
		),
	};


	public static final RFC9830TestVector[] Secp256k1HashToCurveTestVectors = new RFC9830TestVector[]{
		new RFC9830TestVector(
			"QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_",
			"",
			new byte[][]{
				Hex.decode("6b0f9910dd2ba71c78f2ee9f04d73b5f4c5f7fc773a701abea1e573cab002fb3"),
				Hex.decode("1ae6c212e08fe1a5937f6202f929a2cc8ef4ee5b9782db68b0d5799fd8f09e16"),
			},
			Hex.decode("c1cae290e291aee617ebaef1be6d73861479c48b841eaba9b7b5852ddfeb1346"),
			Hex.decode("64fa678e07ae116126f08b022a94af6de15985c996c3a91b64c406a960e51067")
		),
		new RFC9830TestVector(
			"QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_",
			"abc",
			new byte[][]{
				Hex.decode("128aab5d3679a1f7601e3bdf94ced1f43e491f544767e18a4873f397b08a2b61"),
				Hex.decode("5897b65da3b595a813d0fdcc75c895dc531be76a03518b044daaa0f2e4689e00"),
			},
			Hex.decode("3377e01eab42db296b512293120c6cee72b6ecf9f9205760bd9ff11fb3cb2c4b"),
			Hex.decode("7f95890f33efebd1044d382a01b1bee0900fb6116f94688d487c6c7b9c8371f6")
		),
		new RFC9830TestVector(
			"QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_",
			"abcdef0123456789",
			new byte[][]{
				Hex.decode("ea67a7c02f2cd5d8b87715c169d055a22520f74daeb080e6180958380e2f98b9"),
				Hex.decode("7434d0d1a500d38380d1f9615c021857ac8d546925f5f2355319d823a478da18"),
			},
			Hex.decode("bac54083f293f1fe08e4a70137260aa90783a5cb84d3f35848b324d0674b0e3a"),
			Hex.decode("4436476085d4c3c4508b60fcf4389c40176adce756b398bdee27bca19758d828")
		),
		new RFC9830TestVector(
			"QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_",
			"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
			new byte[][]{
				Hex.decode("eda89a5024fac0a8207a87e8cc4e85aa3bce10745d501a30deb87341b05bcdf5"),
				Hex.decode("dfe78cd116818fc2c16f3837fedbe2639fab012c407eac9dfe9245bf650ac51d"),
			},
			Hex.decode("e2167bc785333a37aa562f021f1e881defb853839babf52a7f72b102e41890e9"),
			Hex.decode("f2401dd95cc35867ffed4f367cd564763719fbc6a53e969fb8496a1e6685d873")
		),
		new RFC9830TestVector(
			"QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_",
			"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			new byte[][]{
				Hex.decode("8d862e7e7e23d7843fe16d811d46d7e6480127a6b78838c277bca17df6900e9f"),
				Hex.decode("68071d2530f040f081ba818d3c7188a94c900586761e9115efa47ae9bd847938"),
			},
			Hex.decode("e3c8d35aaaf0b9b647e88a0a0a7ee5d5bed5ad38238152e4e6fd8c1f8cb7c998"),
			Hex.decode("8446eeb6181bf12f56a9d24e262221cc2f0c4725c7e3803024b5888ee5823aa6")
		),
	};

	public static final RFC9830TestVector[] Secp256k1EncodeToCurveTestVectors = new RFC9830TestVector[]{
		new RFC9830TestVector(
			"QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_NU_",
			"",
			new byte[][]{
				Hex.decode("0137fcd23bc3da962e8808f97474d097a6c8aa2881fceef4514173635872cf3b"),
			},
			Hex.decode("a4792346075feae77ac3b30026f99c1441b4ecf666ded19b7522cf65c4c55c5b"),
			Hex.decode("62c59e2a6aeed1b23be5883e833912b08ba06be7f57c0e9cdc663f31639ff3a7")
		),
		new RFC9830TestVector(
			"QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_NU_",
			"abc",
			new byte[][]{
				Hex.decode("e03f894b4d7caf1a50d6aa45cac27412c8867a25489e32c5ddeb503229f63a2e"),
			},
			Hex.decode("3f3b5842033fff837d504bb4ce2a372bfeadbdbd84a1d2b678b6e1d7ee426b9d"),
			Hex.decode("902910d1fef15d8ae2006fc84f2a5a7bda0e0407dc913062c3a493c4f5d876a5")
		),
		new RFC9830TestVector(
			"QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_NU_",
			"abcdef0123456789",
			new byte[][]{
				Hex.decode("e7a6525ae7069ff43498f7f508b41c57f80563c1fe4283510b322446f32af41b"),
			},
			Hex.decode("07644fa6281c694709f53bdd21bed94dab995671e4a8cd1904ec4aa50c59bfdf"),
			Hex.decode("c79f8d1dad79b6540426922f7fbc9579c3018dafeffcd4552b1626b506c21e7b")
		),
		new RFC9830TestVector(
			"QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_NU_",
			"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
			new byte[][]{
				Hex.decode("d97cf3d176a2f26b9614a704d7d434739d194226a706c886c5c3c39806bc323c"),
			},
			Hex.decode("b734f05e9b9709ab631d960fa26d669c4aeaea64ae62004b9d34f483aa9acc33"),
			Hex.decode("03fc8a4a5a78632e2eb4d8460d69ff33c1d72574b79a35e402e801f2d0b1d6ee")
		),
		new RFC9830TestVector(
			"QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_NU_",
			"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			new byte[][]{
				Hex.decode("a9ffbeee1d6e41ac33c248fb3364612ff591b502386c1bf6ac4aaf1ea51f8c3b"),
			},
			Hex.decode("17d22b867658977b5002dbe8d0ee70a8cfddec3eec50fb93f36136070fd9fa6c"),
			Hex.decode("e9178ff02f4dab73480f8dd590328aea99856a7b6cc8e5a6cdf289ecc2a51718")
		),
	};



	/**
	 *
	 * @param htc
	 * @param vectors
	 */
	private void runRFC9830Vectors(ECCurveHasher htc, RFC9830TestVector[] vectors) {
		for (int tidx = 0; tidx < vectors.length; tidx++) {
			final var vector = vectors[tidx];
			final var mode = StringUtils.substring(vector.DST(), -4);
			final var msg = vector.msg().getBytes(StandardCharsets.UTF_8);
			final var DST = vector.DST().getBytes(StandardCharsets.UTF_8);

			// First check hashToField implementation used by either modes internally
			if (vector.DST().contains("secp256k1")) {
				// Not supported for secp256k1, throws exception
				assertThrows(UnsupportedOperationException.class, () -> htc.hashToField(msg, DST, vector.u().length));
			} else {
				final var u = assertDoesNotThrow(() -> htc.hashToField(msg, DST, vector.u().length));
				for (int i = 0; i < u.length; i++) {
					final int idx = i;
					assertArrayEquals(u[i][0].getEncoded(), vector.u()[i], () -> String.format("%s-%s u[%d] is invalid", htc.getCurveName(), mode, idx));
				}
			}

			final var cidx = tidx;
			switch (mode) {
			case "_RO_": {
				final var p = htc.hashToCurve(msg, DST);
				assertArrayEquals(p.getAffineXCoord().getEncoded(), vector.px(), () -> String.format("#%d %s-%s P.x is invalid", cidx, htc.getCurveName(), mode));
				assertArrayEquals(p.getAffineYCoord().getEncoded(), vector.py(), () -> String.format("#%d %s-%s P.y is invalid", cidx, htc.getCurveName(), mode));
				break;
			}
			case "_NU_": {
				final var p = htc.encodeToCurve(msg, DST);
				assertArrayEquals(p.getAffineXCoord().getEncoded(), vector.px(), () -> String.format("#%d %s-%s P.x is invalid", cidx, htc.getCurveName(), mode));
				assertArrayEquals(p.getAffineYCoord().getEncoded(), vector.py(), () -> String.format("#%d %s-%s P.y is invalid", cidx, htc.getCurveName(), mode));
				break;
			}
			default:
				throw new IllegalArgumentException("Invalid mode '" + mode + "'");
			}
		}
	}


	@Test
	void testP256HashToCurveRFC9830() {
		final var htc = ECCurveHasher.createP256();
		runRFC9830Vectors(htc, P256HashToCurveTestVectors);
	}

	@Test
	void testP256EncodeToCurveRFC9830() {
		final var htc = ECCurveHasher.createP256();
		runRFC9830Vectors(htc, P256EncodeToCurveTestVectors);
	}

	@Test
	void testP384HashToCurveRFC9830() {
		final var htc = ECCurveHasher.createP384();
		runRFC9830Vectors(htc, P384HashToCurveTestVectors);
	}

	@Test
	void testP384EncodeToCurveRFC9830() {
		final var htc = ECCurveHasher.createP384();
		runRFC9830Vectors(htc, P384EncodeToCurveTestVectors);
	}

	@Test
	void testP521HashToCurveRFC9830() {
		final var htc = ECCurveHasher.createP521();
		runRFC9830Vectors(htc, P521HashToCurveTestVectors);
	}

	@Test
	void testP521EncodeToCurveRFC9830() {
		final var htc = ECCurveHasher.createP521();
		runRFC9830Vectors(htc, P521EncodeToCurveTestVectors);
	}

	@Test
	void testSecp256k1HashToCurveRFC9830() {
		final var htc = ECCurveHasher.createSecp256k1();
		runRFC9830Vectors(htc, Secp256k1HashToCurveTestVectors);
	}

	@Test
	void testSecp256k1EncodeToCurveRFC9830() {
		final var htc = ECCurveHasher.createSecp256k1();
		runRFC9830Vectors(htc, Secp256k1EncodeToCurveTestVectors);
	}
}
