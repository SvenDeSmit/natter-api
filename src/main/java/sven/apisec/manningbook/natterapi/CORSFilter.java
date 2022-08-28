package sven.apisec.manningbook.natterapi;

import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import spark.Filter;
import spark.Request;
import spark.Response;
import sven.apisec.manningbook.natterapi.controller.TokenController;

import static spark.Spark.*;

public class CORSFilter implements Filter {

	private static final Logger logger = LoggerFactory.getLogger(CORSFilter.class); 

	private final Set<String> allowedOrigins;
	
	public CORSFilter(Set<String> allowedOrigins) {
		logger.info("Allowed origins = "+allowedOrigins.toString());
		this.allowedOrigins = allowedOrigins;
	}


	@Override
	public void handle(Request request, Response response) throws Exception {
		var origin = request.headers("Origin");
		logger.info("Receiving a request with origin = "+origin);
		if (origin != null && allowedOrigins.contains(origin)) {
			response.header("Access-Control-Allow-Origin", origin);
			//response.header("Access-Control-Allow-Credentials", "true");
			response.header("Vary", "Origin");		
			logger.info("Normal CORS response headers set");
		}
		
		if(isPreflightRequest(request)) {
			if (origin == null || !allowedOrigins.contains(origin)) {
				logger.info("Invalid origin value in preflight request");
				spark.Spark.halt(403); // Forbidden
			}
			
			response.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
			response.header("Access-Control-Allow-Methods", "GET, POST, DELETE");
			logger.info("Preflight request CORS response headers set");
			spark.Spark.halt(204); // No content			
		}
	}
	
	private boolean isPreflightRequest(Request request) {
		boolean res = "OPTIONS".equals(request.requestMethod()) && request.headers().contains("Access-Control-Request-Method");
		logger.info("Is request a preflight request? "+res);
		return res;
	}

}
