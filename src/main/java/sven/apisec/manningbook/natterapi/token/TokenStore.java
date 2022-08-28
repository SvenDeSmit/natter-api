package sven.apisec.manningbook.natterapi.token;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.*;

import spark.Request;

public interface TokenStore {
	
	String create(Request request, Token token);
	Optional<Token> read(Request request,String tokenId);
	void revoke(Request request,String tokenId);
	
	class Token {
		public final Instant expiry;
		public final String username;
		public final Map<String, String> attributes;
		
		
		public Token(Instant expiry, String username) {
			super();
			this.expiry = expiry;
			this.username = username;
			this.attributes = new ConcurrentHashMap<String, String>();
		}
	}
}
