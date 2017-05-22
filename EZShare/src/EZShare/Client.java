package EZShare;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.net.Socket;
import java.net.UnknownHostException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.json.*;

import CLI.cliclient;

public class Client {
	private static final Logger log = Logger.getLogger(Client.class.getName());
	private static int MAXFILESIZE = 20 * 1024 * 1024;
	public static void main(String[] args) {
		JSONObject json_args = new cliclient(args).parse(log);
		if (json_args.getBoolean("debug"))
			log.setLevel(Level.ALL);
		else
			
			
			log.setLevel(Level.INFO);
		String ip = json_args.getString("host");
		int port = json_args.getInt("port");
		log.log(Level.WARNING, "connecting to " + ip + ":" + port);
		try {
			
			System.setProperty("javax.net.ssl.trustStore", "clientKeyStore/client.jks");
			SSLSocketFactory sslsocketfactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
			SSLSocket socket = (SSLSocket) sslsocketfactory.createSocket(ip, port);
			
			// Output and Input Stream sunrise.cis.unimelb.edu.au:3780
			DataInputStream input = new DataInputStream(socket.getInputStream());
			DataOutputStream output = new DataOutputStream(socket.getOutputStream());
			JSONObject json_output = new JSONObject();

			// call functions according to input args
			if (json_args.has("exchange")) {
				json_output = exchange(json_args);
			} else if (json_args.has("fetch")) {
				json_output = fetch(json_args);
			} else if (json_args.has("publish")) {
				json_output = publish(json_args);
			} else if (json_args.has("query")) {
				json_output = query(json_args);
			} else if (json_args.has("remove")) {
				json_output = remove(json_args);
			} else if (json_args.has("share")) {
				json_output = share(json_args);
			} else
				;
			output.writeUTF(json_output.toString());
			output.flush();
			log.log(Level.INFO, "[sent]:" + json_output.toString());

			if (json_args.has("fetch")) {
				// Print out results received from server..
				boolean startDownload = false;
				boolean alreadyDownload = false;
				while (true) {
					if (input.available() > 0) {
						String result = input.readUTF();
						log.log(Level.INFO, "[received]:" + result);
						JSONObject command = new JSONObject(result);
						// Check whether the server is sending file
						if (startDownload == false) {
							if (command.getString("response").equals("success")) {
								startDownload = true;
								continue;
							}
						}

						if (startDownload == true && alreadyDownload == false) {

							// Change file location here!!!
							if (command.has("uri")) {
								String fileURI = command.getString("uri");
								String fileName = null;
								if (fileURI.lastIndexOf("\\") > 0)
									fileName = fileURI.substring(fileURI.lastIndexOf("\\") + 1, fileURI.length());
								else
									fileName = fileURI.substring(fileURI.lastIndexOf("/") + 1, fileURI.length());
								String fileLocation = System.getProperty("user.dir") + File.separator + fileName;

								RandomAccessFile downloadingFile = new RandomAccessFile(fileLocation, "rw");
								log.log(Level.INFO, "start download");
								int fileSize = (int) command.get("resourceSize");

								byte[] receiveBuffer = new byte[MAXFILESIZE];
								int num;
								while ((num = input.read(receiveBuffer)) > 0) {
									// Write the received bytes into the
									// RandomAccessFile
									downloadingFile.write(Arrays.copyOf(receiveBuffer, num));

									// Reduce the file size left to read..
									fileSize -= num;

									// If you're done then break
									if (fileSize == 0) {
										break;
									}
								}
								downloadingFile.close();
								alreadyDownload = true;
								log.log(Level.INFO, "file saved to :" + fileLocation);
							}

						}
						if (startDownload == true && alreadyDownload == true) {
							JSONObject fetchResult = new JSONObject();
							fetchResult.put("resultSize", 1);
							log.log(Level.INFO, "[received]:" + fetchResult);
							break;
						}
					}
				}
			} else if(json_args.has("query")){
				int k = 0;
				while (k < 20) {
					if (input.available() > 0) {
						String message = input.readUTF();
						log.log(Level.INFO, "[received]:" + message);
					}
					Thread.sleep(100);
					k++;
				}
			} else {
				while (true) {
					if (input.available() > 0) {
						String message = input.readUTF();
						log.log(Level.INFO, "[received]:" + message);
						 break;
					}
					Thread.sleep(100);
				}

			}
		} catch (UnknownHostException e) {
			log.log(Level.WARNING, e.toString());
		} catch (IOException e) {
			log.log(Level.WARNING, e.toString());
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			log.log(Level.WARNING, e.toString());
		}
	}

	private static JSONObject publish(JSONObject input) {
		JSONObject output = new JSONObject();
		String[] tags = {};

		// initialise
		String publish_name = "";
		String publish_description = "";
		String publish_uri = "";
		String publish_channel = "";
		String publish_owner = "";
		String publish_ezserver = null;

		if (input.has("name"))
			publish_name = input.getString("name");
		if (input.has("tags"))
			tags = input.getString("tags").split(",");
		if (input.has("description"))
			publish_description = input.getString("description");
		if (input.has("uri")){
			publish_uri = input.getString("uri");
		}
		if (input.has("channel"))
			publish_channel = input.getString("channel");
		if (input.has("owner"))
			publish_owner = input.getString("owner");
		if (input.has("ez server"))
			publish_ezserver = input.getString("ez server");

		// output
		JSONObject resource = new JSONObject();
		output.put("command", "PUBLISH");
		resource.put("name", publish_name);
		resource.put("tags", tags);
		resource.put("description", publish_description);
		resource.put("uri", publish_uri);
		resource.put("channel", publish_channel);
		resource.put("owner", publish_owner);
		resource.put("ezserver", publish_ezserver);
		output.put("resource", resource);
		return output;

	}

	private static JSONObject remove(JSONObject input) {
		JSONObject output = new JSONObject();
		// initialise
		String remove_name = "";
		String[] remove_tags = null;
		String remove_description = "";
		String remove_uri = "";
		String remove_channel = "";
		String remove_owner = "";
		String remove_ezserver = null;

		if (input.has("name"))
			remove_name = input.getString("name");
		if (input.has("tags"))
			remove_tags = input.getString("tags").split(",");
		if (input.has("description"))
			remove_description = input.getString("description");
		if (input.has("uri"))
			remove_uri = input.getString("uri");
		if (input.has("channel"))
			remove_channel = input.getString("channel");
		if (input.has("owner"))
			remove_owner = input.getString("owner");
		if (input.has("ez server"))
			remove_ezserver = input.getString("ez server");
		// output
		JSONObject resource = new JSONObject();
		output.put("command", "REMOVE");
		resource.put("name", remove_name);
		resource.put("tags", remove_tags);
		resource.put("description", remove_description);
		resource.put("uri", remove_uri);
		resource.put("channel", remove_channel);
		resource.put("owner", remove_owner);
		resource.put("ez server", remove_ezserver);
		output.put("resource", resource);
		return output;
	}

	private static JSONObject share(JSONObject input) {
		JSONObject output = new JSONObject();
		output.put("command", "SHARE");
		try {
			output.put("secret", input.getString("secret"));

			JSONObject resource = new JSONObject();
			if (input.has("description"))
				resource.put("description", input.getString("description"));
			if (input.has("uri"))
				resource.put("uri", input.getString("uri"));
			if (input.has("channel"))
				resource.put("channel", input.getString("channel"));
			if (input.has("owner"))
				resource.put("owner", input.getString("owner"));
			if (input.has("ezserver"))
				resource.put("ezserver", input.getString("ezserver"));
			if (input.has("tags")) {
				String[] tags = input.getString("tags").split(",");
				resource.put("tags", tags);
			}
			output.put("resource", resource);
		} catch (JSONException e) {
			log.log(Level.SEVERE, e.toString());
		}
		return output;
	}

	private static JSONObject query(JSONObject input) {
		JSONObject output = new JSONObject();
		JSONObject resourceTemplate = new JSONObject();

		String query_name = "";
		boolean query_relay = true;
		String[] tagsArray = null;
		ArrayList<String> tagsList = null;
		String query_description = "";
		String query_uri = "";
		String query_channel = "";
		String query_owner = "";
		String query_ezserver = null;

		if (input.has("name")) {
			query_name = input.getString("name");
		}
		if (input.has("relay")) {
			String query_relay_String = input.getString("relay");
			if (query_relay_String.equals("false")) {
				query_relay = false;
			}
		}
		if (input.has("tags")) {
			tagsArray = input.getString("tags").split(",");
			tagsList = (ArrayList<String>) Arrays.asList(tagsArray);
		}
		if (input.has("description")) {
			query_description = input.getString("description");
		}
		if (input.has("uri")) {
			query_uri = input.getString("uri");
		}
		if (input.has("channel")) {
			query_channel = input.getString("channel");
		}
		if (input.has("owner")) {
			query_owner = input.getString("owner");
		}
		if (input.has("ezserver")) {
			query_ezserver = input.getString("ezserver");
		}

		// output
		output.put("command", "QUERY");
		output.put("relay", query_relay);
		resourceTemplate.put("name", query_name);
		resourceTemplate.put("tags", tagsList);
		resourceTemplate.put("description", query_description);
		resourceTemplate.put("uri", query_uri);
		resourceTemplate.put("channel", query_channel);
		resourceTemplate.put("owner", query_owner);
		resourceTemplate.put("ezserver", query_ezserver);
		output.put("resourceTemplate", resourceTemplate);

		return output;
	}

	private static JSONObject fetch(JSONObject input) {
		JSONObject output = new JSONObject();
		JSONObject resourceTemplate = new JSONObject();

		String fetch_name = "";
		String[] tagsArray = null;
		ArrayList<String> tagsList = null;
		String fetch_description = "";
		String fetch_uri = "";
		String fetch_channel = "";
		String fetch_owner = "";
		String fetch_ezserver = null;

		if (input.has("name")) {
			fetch_name = input.getString("name");
		}
		if (input.has("tags")) {
			tagsArray = input.getString("tags").split(",");
			tagsList = (ArrayList<String>) Arrays.asList(tagsArray);
		}
		if (input.has("description")) {
			fetch_description = input.getString("description");
		}
		if (input.has("uri")) {
			fetch_uri = input.getString("uri");
		}
		if (input.has("channel")) {
			fetch_channel = input.getString("channel");
		}
		if (input.has("owner")) {
			fetch_owner = input.getString("owner");
		}
		if (input.has("ezserver")) {
			fetch_ezserver = input.getString("ezserver");
		}

		// output
		output.put("command", "FETCH");
		resourceTemplate.put("name", fetch_name);
		resourceTemplate.put("tags", tagsList);
		resourceTemplate.put("description", fetch_description);
		resourceTemplate.put("uri", fetch_uri);
		resourceTemplate.put("channel", fetch_channel);
		resourceTemplate.put("owner", fetch_owner);
		resourceTemplate.put("ezserver", fetch_ezserver);
		output.put("resourceTemplate", resourceTemplate);

		return output;
	}

	private static JSONObject exchange(JSONObject input) {
		JSONObject output = new JSONObject();
		output.put("command", "EXCHANGE");
		JSONArray server_list = new JSONArray();

		String[] string_server = input.getString("serverList").split(",");
		int string_serverLength = string_server.length;

		try {
			for (String tmp : string_server) {

				JSONObject tmp_json = new JSONObject();
				String[] tuple = tmp.split(":");
				tmp_json.put("hostname", tuple[0]);
				tmp_json.put("port", Integer.valueOf(tuple[1]));
				server_list.put(tmp_json);

			}
		} catch (Exception e) {
			log.log(Level.WARNING, "response: error, errorMessage: invalid server list");
		}

		if (string_serverLength == server_list.length()) {
			output.put("serverList", server_list);
		} else {
			output.put("serverList", new JSONArray());
		}

		return output;
	}

}
