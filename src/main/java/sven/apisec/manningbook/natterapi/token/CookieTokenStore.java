package sven.apisec.manningbook.natterapi.token;

import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

import spark.Request;

public class CookieTokenStore implements SecureTokenStore {

	private static final Logger logger = LoggerFactory.getLogger(CookieTokenStore.class); 

	@Override
	public String create(Request request, Token token) {
		
		var session = request.session(false);
		if (session != null) {
			session.invalidate();
		}
				
		session = request.session(true);
		
		session.attribute("username",token.username);
		session.attribute("expiry",token.expiry);
		session.attribute("attrs",token.attributes);
		
		logger.info("Session created for user "+ token.username + " - " + session.id());
		
		var encodedToken = Base64url.encode(sha256(session.id()));
		
		logger.info("Encoded token created "+ encodedToken);
		
		return encodedToken;
	}

	@Override
	public Optional<Token> read(Request request, String tokenId) {
		// TODO Auto-generated method stub
		var session = request.session(false);
		if (session == null) {
			logger.info("No active session found for user");
			return Optional.empty();
		}
		
		logger.info("Active session found for user "+session.attribute("username")+" - "+session.id());
		
		
		var provided = Base64url.decode(tokenId);
		var computed = sha256(session.id());
		
		if (!MessageDigest.isEqual(computed, provided)) {
			return Optional.empty();
		}
				
		var token = new Token(session.attribute("expiry"),session.attribute("username"));
		token.attributes.putAll(session.attribute("attrs"));
		return Optional.of(token);
	}
		

	@Override
	public void revoke(Request request, String tokenId) {
		// TODO Auto-generated method stub
		var session = request.session(false);
		if (session == null) {
			logger.info("No active session found for user");
			return;
		}
		
		logger.info("Active session found for user "+session.attribute("username")+" - "+session.id());
		
		
		var provided = Base64url.decode(tokenId);
		var computed = sha256(session.id());
		
		if (!MessageDigest.isEqual(computed, provided)) {
			return;
		}

		logger.info("Valid X-CSRF-Token found, invalidating session for user "+session.attribute("username")+" - "+session.id());	
		session.invalidate();
		
	}

	static byte[] sha256(String tokenId) {
		try {
			var sha256 = MessageDigest.getInstance("SHA-256");
			return sha256.digest(tokenId.getBytes(StandardCharsets.UTF_8));
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
	}
}
