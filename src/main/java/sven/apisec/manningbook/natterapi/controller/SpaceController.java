package sven.apisec.manningbook.natterapi.controller;

import java.sql.SQLException;
import java.time.Instant;

import org.dalesbred.Database;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import spark.Request;
import spark.Response;
import sven.apisec.manningbook.natterapi.controller.AuditController.LogRecord;

public class SpaceController {

	private static final Logger logger = LoggerFactory.getLogger(SpaceController.class); 

	private final Database database;
	
	public SpaceController(Database database) {
		this.database = database;
	}
	
	public JSONObject createSpace(Request request, Response response) throws SQLException {
		var json = new JSONObject(request.body());
		var spaceName = json.getString("name");
		var owner = json.getString("owner");
		var subject = request.attribute("subject");

		logger.info(String.format("Creating space %s for owner %s with user %s ", spaceName, owner, subject));

		if (!owner.equals(subject)) {
			throw new IllegalArgumentException("owner must match authenticated user");
		}
		
		if(spaceName.length() > 255) {
			//throw new IllegalArgumentException("space name too long: "+spaceName);
			// don't return possibly long input
			throw new IllegalArgumentException("space name too long");
		}

		if(owner.length() > 30) {
			//throw new IllegalArgumentException("owner name too long: "+owner);
			// don't return possibly long input
			throw new IllegalArgumentException("owner name too long: " + owner);
		}
		
		if(!owner.matches("[a-zA-Z][a-zA-Z0-9]{1,29}")) {
			//throw new IllegalArgumentException("invalid owner name: "+owner);			
			// don't return possibly long input
			throw new IllegalArgumentException("owner name has invalid characters");
		}
		
		
		return database.withTransaction(tx -> {
			var spaceId = database.findUniqueLong("SELECT NEXT VALUE FOR space_id_seq;");
			//database.updateUnique("INSERT INTO spaces(space_id,name,owner) VALUES("+spaceId+", '"+spaceName+"', '"+owner+"');");
			// USE PREPARED STATEMENT
			database.updateUnique("INSERT INTO spaces(space_id,name,owner) VALUES(?,?,?);",spaceId,spaceName,owner);
			logger.info(String.format("Space %s for owner %s created", spaceName, owner));
			
			database.updateUnique("INSERT INTO permissions(space_id,user_id,perms) VALUES(?,?,?);",spaceId,owner,"rwd");
			logger.info(String.format("Adding RWD access for %s in space %s", owner, spaceName));

			response.status(201);
			response.header("Location","/spaces/"+spaceId);
			
			return new JSONObject().put("name",spaceName).put("uri","/spaces/"+spaceId);
		});
	}
	
	public JSONObject addMember(Request request, Response response) throws SQLException {
		var json = new JSONObject(request.body());
		var spaceId = Long.parseLong(request.params(":spaceId"));
		var userToAdd = json.getString("username");
		var perms = json.getString("permissions");
		var subject = request.attribute("subject");
		
		logger.info(String.format("Adding member %s to space with ID %d with permissions %s ...", userToAdd,spaceId,perms));

		if (!userToAdd.equals(subject)) {
			throw new IllegalArgumentException("member must match authenticated user");
		}
		
		if (!perms.matches("r?w?d?")) {
			throw new IllegalArgumentException("invalid permisions");
		}
		
		database.updateUnique("INSERT INTO permissions(space_id,user_id,perms) VALUES(?,?,?);",spaceId,userToAdd,perms);
		logger.info(String.format("Member %s added to space with ID %d with permissions %s ...", userToAdd,spaceId,perms));
		
		response.status(200);
		
		var res = new JSONObject()
				.put("username",userToAdd)
				.put("permissions", perms);
		return res;
	}

	/*
	 CREATE TABLE messages(
	space_id INT NOT NULL REFERENCES spaces(space_id),
	msg_id INT PRIMARY KEY,
	author VARCHAR(30) NOT NULL,
	msg_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	msg_text VARCHAR(1024) NOT NULL
	);
	 */
	
	public JSONObject addMessage(Request request, Response response) throws SQLException {
		var json = new JSONObject(request.body());
		var spaceId = Long.parseLong(request.params(":spaceId"));
		var author = request.attribute("subject");
		var text = json.getString("text");
		logger.info(String.format("Adding a message for author %s to space with ID %d ...", author,spaceId));
		
		if(text.length() > 1024) {
			throw new IllegalArgumentException("message is too long");
		}
		
		var msgId = database.findUniqueLong("SELECT NEXT VALUE FOR msg_id_seq;");	
		database.updateUnique("INSERT INTO messages(space_id,msg_id,author,msg_text) VALUES(?,?,?,?);",spaceId,msgId,author,text);


		logger.info(String.format("Message added for author %s to space with ID %d", author,spaceId));
				
		response.status(200);
		
		return new JSONObject().put("message-uri","/spaces/"+spaceId+"/messages/"+msgId);
	}
	
	public JSONObject readMessageById(Request request, Response response) throws SQLException {
		var user = request.attribute("subject");
		var spaceId = Long.parseLong(request.params(":spaceId"));
		var msgId = Long.parseLong(request.params(":msgId"));
		logger.info(String.format("Reading message with ID %d for user %s in space with ID %d ...", msgId,user,spaceId));

		var msg = database.findUnique(Message.class
				,"SELECT space_id, msg_id, author, msg_text, msg_time FROM messages WHERE msg_id = ?"
				,msgId);
		
		logger.info(String.format("Message with ID %d read for user %s in space with ID %d ...", msgId,user,spaceId));
		
		response.status(200);
		
		return msg.toJson();
	}


	public JSONObject findMessages(Request request, Response response) throws SQLException {
		return null;
	}

	public JSONObject deleteMessage(Request request, Response response) throws SQLException {
		return null;
	}

	public static class Message {
		private final Long spaceId;
		private final Long msgId;
		private final String author;
		private final String text;
		private final Instant auditTime;
		
		
		public Message(Long spaceId, Long msgId, String author, String text, Instant auditTime) {
			super();
			this.spaceId = spaceId;
			this.msgId = msgId;
			this.author = author;
			this.text = text;
			this.auditTime = auditTime;
		}


		JSONObject toJson() {
			var json = new JSONObject()
					.put("spaceId", spaceId)
					.put("msgId", msgId)
					.put("author", author)
					.put("text", text)
					.put("time", auditTime.toString());
			return json;
		}		
	}

	
}
