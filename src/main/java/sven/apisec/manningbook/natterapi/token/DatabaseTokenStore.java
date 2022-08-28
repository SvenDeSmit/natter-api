package sven.apisec.manningbook.natterapi.token;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Optional;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.dalesbred.Database;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import spark.Request;
import sven.apisec.manningbook.natterapi.controller.TokenController;

public class DatabaseTokenStore implements ConfidentialTokenStore {

	private static final Logger logger = LoggerFactory.getLogger(DatabaseTokenStore.class); 

	private final Database database;
	private final SecureRandom secureRandom;
	
	
	public DatabaseTokenStore(Database database) {
		this.database = database;
		this.secureRandom = new SecureRandom();
		Executors.newSingleThreadScheduledExecutor().scheduleAtFixedRate(this::deleteExpiredTokens, 10, 10, TimeUnit.MINUTES);
	}

	@Override
	public String create(Request request, Token token) {
		var tokenId = randomId();
		var attrs = new JSONObject(token.attributes).toString();
		
		var hash = hash(tokenId); 
		
		database.updateUnique("INSERT INTO tokens(token_id, user_id, expiry, attributes) VALUES(?,?,?,?);",hash,token.username,token.expiry,attrs);
		logger.info(String.format("Token created and stored for user %s with ID: %s", token.username, tokenId));			

		return tokenId;
	}

	@Override
	public Optional<Token> read(Request request, String tokenId) {
		logger.info(String.format("Reading token with ID %s for user %s ", tokenId, request.attribute("subject")));	
		
		var hash = hash(tokenId); 
				
		var res = database.findOptional(this::readToken,"SELECT user_id,expiry,attributes FROM tokens WHERE token_id = ?;",hash); 	
		return res;
	}
	
	private Token readToken(ResultSet resultSet) throws SQLException {
		var username = resultSet.getString(1);
		var expiry = resultSet.getTimestamp(2).toInstant();
		var json = new JSONObject(resultSet.getString(3));
		
		logger.info(String.format("Token read for user %s", username));			

		var token = new Token(expiry,username);
		for (var key: json.keySet()) {
			token.attributes.put(key,json.getString(key));
		}
		
		return token;
	}

	@Override
	public void revoke(Request request, String tokenId) {
		var hash = hash(tokenId); 

		database.update("DELETE FROM tokens WHERE token_id = ?;",hash); 	
		logger.info(String.format("Token with ID %s removed from database", tokenId));			
		
	}
	
	private String randomId() {
		var bytes = new byte[20];
		new SecureRandom().nextBytes(bytes);
		var res = Base64url.encode(bytes);
		logger.info("Token generated: "+res);
		return res;
	}
	
	public void deleteExpiredTokens( ) {
		logger.info("Deleting expired tokens ...");
		database.update("DELETE FROM tokens WHERE expiry < current_timestamp");
	}
	
	private static String hash(String tokenId) {
		var hash = sha256(tokenId);
		var encHash = Base64url.encode(hash);
		return encHash;
	}

	private static byte[] sha256(String tokenId) {
		try {
			var sha256 = MessageDigest.getInstance("SHA-256");
			return sha256.digest(tokenId.getBytes(StandardCharsets.UTF_8));
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
	}

	
}
