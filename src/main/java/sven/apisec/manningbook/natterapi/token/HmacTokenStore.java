package sven.apisec.manningbook.natterapi.token;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.MessageDigest;
import java.util.Optional;

import javax.crypto.Mac;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import spark.Request;

public class HmacTokenStore implements SecureTokenStore {

	private static final Logger logger = LoggerFactory.getLogger(HmacTokenStore.class); 

	private final ConfidentialTokenStore delegate;
	private final Key macKey;	
	
	public HmacTokenStore(ConfidentialTokenStore delegate, Key macKey) {
		this.delegate = delegate;
		this.macKey = macKey;
	}

	@Override
	public String create(Request request, Token token) {		
		var tokenId = delegate.create(request, token);
		logger.info(String.format("Creating HMAC for token %s", token));			
		var tag = hmac(tokenId);
		logger.info("HMAC tag = "+tag);
		var base64TaggedToken = Base64url.encode(tag);
		logger.info("Base64 tag = "+base64TaggedToken);		
		var taggedToken = tokenId + '.' + base64TaggedToken;
		logger.info(String.format("HMAC Token created: %s", taggedToken));			
		
		return taggedToken;
	}

	@Override
	public Optional<Token> read(Request request, String tokenId) {
		logger.info(String.format("Reading & validating HMAC Token: %s", tokenId));			

		var index = tokenId.lastIndexOf('.');
		if (index == -1) {
			return Optional.empty();
		}
		var tokenIdWithoutHMAC = tokenId.substring(0,index);
		var hmacToken = tokenId.substring(index+1);
		logger.info("hmac token = "+hmacToken);			
		
		var providedHMAC = Base64url.decode(hmacToken);
		logger.info("provided HMAC = "+providedHMAC);			
		
		var computedHMAC = hmac(tokenIdWithoutHMAC);

		logger.info(String.format("Reading & validating HMAC Token : %s", tokenId));			
	
		if(!MessageDigest.isEqual(providedHMAC, computedHMAC)) {
			return Optional.empty();			
		}

		logger.info(String.format("HMAC Token successfully checked for user %s with ID: %s", request.attribute("subject"), tokenId));			

		return delegate.read(request,tokenIdWithoutHMAC);
	}

	@Override
	public void revoke(Request request, String tokenId) {
		logger.info(String.format("Revoking HMAC Token for user %s with ID: %s", request.attribute("subject"), tokenId));			

		var index = tokenId.lastIndexOf('.');
		if (index == -1) {
			return;
		}
		var tokenIdWithoutHMAC = tokenId.substring(0,index);
		
		var providedHMAC = Base64url.decode(tokenId.substring(index+1));
		var computedHMAC = hmac(tokenIdWithoutHMAC);
		
		if(!MessageDigest.isEqual(providedHMAC, computedHMAC)) {
			return;			
		}

		logger.info(String.format("HMAC Token successfully checked for user %s with ID: %s", request.attribute("subject"), tokenId));			

		delegate.revoke(request,tokenIdWithoutHMAC);
	}
	
	private byte[] hmac(String tokenId) {
		try {
			logger.info("Calculating HMAC for token ... "+tokenId);
			var mac = Mac.getInstance(macKey.getAlgorithm());
			mac.init(macKey);
			var res = mac.doFinal(tokenId.getBytes(StandardCharsets.UTF_8));
			logger.info("HMAC calculated: "+res);
			return res;
		} catch(GeneralSecurityException e) {
			throw new RuntimeException(e); 
		}
	}

}
