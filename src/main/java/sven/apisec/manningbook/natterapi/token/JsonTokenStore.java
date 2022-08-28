package sven.apisec.manningbook.natterapi.token;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Optional;

import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import spark.Request;

public class JsonTokenStore implements TokenStore {

	private static final Logger logger = LoggerFactory.getLogger(JsonTokenStore.class); 

	@Override
	public String create(Request request, Token token) {
		var json = new JSONObject();
		json.put("sub", token.username);
		json.put("exp", token.expiry);
		json.put("attrs", token.attributes);

		logger.info(String.format("JSON token created for user %s: %s", token.username, json));			
		
		var jsonBytes = json.toString().getBytes(StandardCharsets.UTF_8);	
		var base64Json = Base64url.encode(jsonBytes);
		logger.info("Base64 JSON token = "+base64Json);
		
		return base64Json;
	}

	@Override
	public Optional<Token> read(Request request, String tokenId) {
		try {
			logger.info(String.format("Reading Base64 JSON token: %s", tokenId));			

			var decoded = Base64url.decode(tokenId);
			var json = new JSONObject(new String(decoded,StandardCharsets.UTF_8));
			logger.info(String.format("JSON token: %s", json));			
			
			//var expiry = Instant.ofEpochSecond(json.getLong("exp"));
			var expiry = Instant.parse(json.getString("exp"));
			logger.info("expiry = "+expiry);
			var username = json.getString("sub");
			logger.info("username = "+username);
			var attrs = json.getJSONObject("attrs");
			
			logger.info("username = "+username);
			
			request.attribute("subject", username);
			logger.info("subject in request = "+request.attribute("subject"));
			
			var token = new Token(expiry,username);
			for (var key : attrs.keySet()) {
				token.attributes.put(key, attrs.getString(key));
			}
			
			return Optional.of(token);
			
		} catch(JSONException e) {
			return Optional.empty();
		} 
		
	}

	@Override
	public void revoke(Request request, String tokenId) {
		// TODO Auto-generated method stub

	}

}
