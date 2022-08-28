package sven.apisec.manningbook.natterapi.controller;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.stream.Collectors;

import org.dalesbred.Database;
import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import spark.Request;
import spark.Response;

public class AuditController {

	private static final Logger logger = LoggerFactory.getLogger(AuditController.class); 
	
	private final Database database;
	
	public AuditController(Database database) {
		this.database = database;				
	}

	public void auditRequestStart(Request request, Response response) {
		database.withVoidTransaction(tx -> {
			var auditId = database.findUniqueLong("SELECT NEXT VALUE FOR audit_id_seq");
			request.attribute("audit_id",auditId);
			database.updateUnique("INSERT INTO audit_log(audit_id,method,path,user_id,audit_time) VALUES(?,?,?,?,current_timestamp)"
					,auditId
					,request.requestMethod()
					,request.pathInfo()
					,request.attribute("subject")
					);
			logger.info("Audit log record created (start)");
		});
	}
	
	public void auditRequestEnd(Request request, Response response) {
		database.updateUnique("INSERT INTO audit_log(audit_id,method,path,status,user_id,audit_time) VALUES(?,?,?,?,?,current_timestamp)"
				,request.attribute("audit_id")
				,request.requestMethod()
				,request.pathInfo()
				,response.status()
				,request.attribute("subject")
				);	
		logger.info("Audit log record created (end)");

	}
	
	public JSONArray readAuditLog(Request request, Response response) {
		logger.info("eadng audit log records ...");

		var since = Instant.now().minus(1, ChronoUnit.HOURS);
		var logs = database.findAll(LogRecord.class
				,"SELECT audit_id, method, path, status, user_id, audit_time FROM audit_log WHERE audit_time >= ?"
				,since);
		var json = new JSONArray(logs.stream().map(LogRecord::toJson).collect(Collectors.toList()));
		return json;
	}
	
	public static class LogRecord {
		private final Long auditId;
		private final String method;
		private final String path;
		private final Integer status;
		private final String user;
		private final Instant auditTime;
		
		public LogRecord(Long auditId, String method, String path, Integer status, String user, Instant auditTime) {
			this.auditId = auditId;
			this.method = method;
			this.path = path;
			this.status = status;
			this.user = user;
			this.auditTime = auditTime;
		}
		
		JSONObject toJson() {
			var json = new JSONObject()
					.put("id", auditId)
					.put("method", method)
					.put("path", path)
					.put("status", status)
					.put("user", user)
					.put("time", auditTime.toString());
			return json;
		}		
	}

}
