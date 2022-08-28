package sven.apisec.manningbook.natterapi.token;

import java.time.Instant;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import spark.Request;
import sven.apisec.manningbook.natterapi.controller.TokenController;

public class DummyTokenStore implements TokenStore {

	private static final Logger logger = LoggerFactory.getLogger(DummyTokenStore.class); 

	@Override
	public String create(Request request, Token token) {
		// TODO Auto-generated method stub
		logger.info("Creating token for user "+request.attribute("subject"));
		return "dummy-token";
	}

	@Override
	public Optional<Token> read(Request request, String tokenId) {
		// TODO Auto-generated method stub
		logger.info("Reading token for user "+request.attribute("subject"));
		Token token = new Token(Instant.now(), request.attribute("subject"));
		return Optional.ofNullable(token);
	}

	@Override
	public void revoke(Request request, String tokenId) {
		// TODO Auto-generated method stub
		
	}
	
	

}
