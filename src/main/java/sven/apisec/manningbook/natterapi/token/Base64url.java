package sven.apisec.manningbook.natterapi.token;

import java.util.Base64;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Base64url {

	private static final Logger logger = LoggerFactory.getLogger(Base64url.class); 

	private static final Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
	private static final Base64.Decoder decoder = Base64.getUrlDecoder();
	
	public static String encode(byte[] data) {
		return encoder.encodeToString(data);
	}
	
	public static byte[] decode(String encoded) {
		logger.info("Decoding "+encoded);
		var res = decoder.decode(encoded);
		logger.info("Decoded "+res);
		return res;
	}

}
