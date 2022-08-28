package sven.apisec.manningbook.natterapi.controller;

import java.time.temporal.ChronoUnit;
import java.util.Set;

import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import spark.*;
import static spark.Spark.*;

import sven.apisec.manningbook.natterapi.token.SecureTokenStore;
import sven.apisec.manningbook.natterapi.token.TokenStore;

import static java.time.Instant.now;

import java.time.Instant;



public class TokenController {

	private static final Logger logger = LoggerFactory.getLogger(TokenController.class); 

	private final SecureTokenStore tokenStore;

	public TokenController(SecureTokenStore tokenStore) {
		this.tokenStore = tokenStore;
	}
	
	public JSONObject login(Request request, Response response) {
		String subject = request.attribute("subject");
		logger.info(subject + " is logging in ...");
		var expiry = now().plus(10,ChronoUnit.MINUTES);
		
		var token = new TokenStore.Token(expiry,subject);
		var scope = request.queryParams("scope");
		logger.info("Scope = "+scope);
		
		if (scope != null) {
			token.attributes.put("scope", scope);
		}
		
		var tokenId = tokenStore.create(request, token);
		
		response.status(201);
		var json = new JSONObject().put("token", tokenId);
		logger.info("Token created for "+subject);
		
		return json;
	}
	
	public JSONObject logout(Request request, Response response) {
		String subject = request.attribute("subject");
		logger.info("Logging out of session for user "+subject);
		
		//var tokenId = request.headers("X-CSRF-Token");
		
		var tokenId = request.headers("Authorization");
		logger.info("Revoking Bearer Token "+tokenId);
		
		if (tokenId == null || !tokenId.startsWith("Bearer ")) 
			throw new IllegalArgumentException("missing token header");

		tokenId = tokenId.substring(7);
		logger.info("Revoking Bearer Token "+tokenId);

		tokenStore.revoke(request, tokenId);
		
		response.status(200);
		return new JSONObject();
	}
	
	public void validateToken(Request request, Response response) {
		logger.info("Validating token (if present) ...");
		
		// var tokenId = request.headers("X-CSRF-Token");
		var tokenId = request.headers("Authorization");
		logger.info("Validating Bearer Token "+tokenId);
		
		if (tokenId == null || !tokenId.startsWith("Bearer ")) return;
		
		tokenId = tokenId.substring(7);
		logger.info("Validating Bearer Token "+tokenId);
		
		tokenStore.read(request, tokenId).ifPresent(token -> {
			logger.info("Token found for user "+ token.username);
			if (Instant.now().isBefore(token.expiry)) {
				request.attribute("subject",token.username);
				token.attributes.forEach(request::attribute);
				logger.info("Token validated and attributes added to request");
			} else {
				response.header("WWW-Authenticate", "Bearer error=\"invalid token\",error_description=\"Expired\"");
				halt(401);
			}
		});
	}
	
	public Filter requireScope(String method,String requiredScope) {
		logger.info("Creating a scope filter for scope "+requiredScope);			
		return (request,response) -> {
			if(!method.equals(request.requestMethod())) {
				return;
			}
							
			var tokenScope = request.<String>attribute("scope");
			logger.info("scopes in request: "+tokenScope);						
			if (tokenScope == null) return;

			if (!Set.of(tokenScope.split(" ")).contains(requiredScope)) {
				logger.info(String.format("Scope missing in request: "+requiredScope));
				response.header("WWW-Authenticate", "Bearer error=\"insufficient scope\",scope=\""+requiredScope+"\"");
				halt(403); // Forbidden				
			} else {
				logger.info("Scope check OK");										
			}
		};
	}
	
	
}
