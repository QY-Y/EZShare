package EZShare;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.RandomAccessFile;
import java.net.Socket;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.json.*;
import java.io.OutputStream;

import CLI.cliclient;

public class Client {
	private static final Logger log = Logger.getLogger(Client.class.getName());
	private static int MAXFILESIZE = 20 * 1024 * 1024;
	private static String id = "";
	private static Socket socket = null;
	private static SSLSocket sslsocket = null;

	public static SSLSocket sslsocket(String ip, int port) {
		// return a SSLServerSocket if success, or null if failed
		Path temp = null;
		try {
			temp = Files.createTempFile("client", ".jks1");
			Files.copy(Thread.currentThread().getContextClassLoader().getResourceAsStream("EZShare/client.jks"), temp,
					StandardCopyOption.REPLACE_EXISTING);
		} catch (IOException e2) {
			// TODO Auto-generated catch block
			e2.printStackTrace();
		}
		System.setProperty("javax.net.ssl.trustStore", temp.toString());
		SSLSocketFactory sslsocketfactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
		try {
			SSLSocket socket = (SSLSocket) sslsocketfactory.createSocket(ip, port);
			socket.setKeepAlive(true);
			socket.setSoTimeout(24 * 3600 * 1000);
			return socket;
		} catch (IOException e) {
			// TODO Auto-generated catch block
			log.log(Level.SEVERE, e.toString());
			System.exit(0);
			e.printStackTrace();
			return null;
		}
	}

	private static JSONObject subscribe(JSONObject input) {
		JSONObject output = new JSONObject();
		JSONObject resourceTemplate = new JSONObject();

		String name = "";
		boolean relay = true;
		String[] tagsArray = null;
		ArrayList<String> tagsList = null;
		String description = "";
		String uri = "";
		String channel = "";
		String owner = "";
		String ezserver = null;
		String uuid = UUID.randomUUID().toString();

		if (input.has("name")) {
			name = input.getString("name");
		}
		if (input.has("relay")) {
			relay = input.getBoolean("relay");
		}
		if (input.has("tags")) {
			tagsArray = input.getString("tags").split(",");
			tagsList = new ArrayList<>(Arrays.asList(tagsArray));
		}
		if (input.has("description")) {
			description = input.getString("description");
		}
		if (input.has("uri")) {
			uri = input.getString("uri");
		}
		if (input.has("channel")) {
			channel = input.getString("channel");
		}
		if (input.has("owner")) {
			owner = input.getString("owner");
		}
		if (input.has("ezserver")) {
			ezserver = input.getString("ezserver");
		}

		// output
		output.put("command", "SUBSCRIBE");
		output.put("relay", relay);
		output.put("id", uuid);
		resourceTemplate.put("name", name);
		resourceTemplate.put("tags", tagsList);
		resourceTemplate.put("description", description);
		resourceTemplate.put("uri", uri);
		resourceTemplate.put("channel", channel);
		resourceTemplate.put("owner", owner);
		resourceTemplate.put("ezserver", ezserver);
		output.put("resourceTemplate", resourceTemplate);
		return output;
	}

	private static void sendsocketssl(SSLSocket client, String msg) {
		try {
			OutputStream outputstream = client.getOutputStream();
			OutputStreamWriter outputstreamwriter = new OutputStreamWriter(outputstream);
			BufferedWriter bufferedwriter = new BufferedWriter(outputstreamwriter);
			bufferedwriter.write(msg + "\n");
			bufferedwriter.flush();
			log.log(Level.INFO, "[sent]:" + msg);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			log.log(Level.WARNING, "[sending failed:]:" + msg);
			e.printStackTrace();
		}
	}

	public static void exit_trigger(String id, SSLSocket sslsocket, Socket client, Boolean sslflag) {
		System.out.println("press enter to exit");
		while (true) {
			try {
				if (System.in.read() == '\n') {
					System.out.println("[enter] pressed, exiting!");
					JSONObject output = new JSONObject();
					output.put("command", "UNSUBSCRIBE");
					output.put("id", id);
					if (sslflag) {
						sendsocketssl(sslsocket, output.toString());
					} else {
						sendsocket(client, output.toString());
					}
					System.exit(0);
				}
			} catch (IOException e) {
				e.printStackTrace();
			}
			try {
				Thread.sleep(100);
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
		}

	}

	private static void sendsocket(Socket client, String string) {
		DataOutputStream output;

		try {
			output = new DataOutputStream(socket.getOutputStream());
			output.writeUTF(string);
			output.flush();
			log.log(Level.INFO, "[sent]:" + string);
		}

		catch (IOException e) {
			log.log(Level.INFO, "[sent failed]:" + string);
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private static void socketsendssl(SSLSocket client, String msg) {
		try {
			OutputStream outputstream = client.getOutputStream();
			OutputStreamWriter outputstreamwriter = new OutputStreamWriter(outputstream);
			BufferedWriter bufferedwriter = new BufferedWriter(outputstreamwriter);
			bufferedwriter.write(msg + "\n");
			bufferedwriter.flush();
			log.log(Level.INFO, "[sent]:" + msg);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			log.log(Level.WARNING, "[sending failed:]:" + msg);
			e.printStackTrace();
		}
	}

	public static void main(String[] args) {
		JSONObject json_args = new cliclient(args).parse(log);
		if (json_args.getBoolean("debug"))
			log.setLevel(Level.ALL);
		else
			log.setLevel(Level.INFO);
		String ip = json_args.getString("host");
		int port = json_args.getInt("port");
		Boolean sslflag = json_args.getBoolean("secure");
		json_args.put("realay", true);

		log.log(Level.WARNING, "connecting to " + ip + ":" + port + ".secure:" + sslflag.toString());
		try {

			DataInputStream input = null;
			DataOutputStream output = null;

			if (sslflag) {
				sslsocket = sslsocket(ip, port);

			} else {
				socket = new Socket(ip, port);
				input = new DataInputStream(socket.getInputStream());
				output = new DataOutputStream(socket.getOutputStream());
			}

			// Output and Input Stream sunrise.cis.unimelb.edu.au:3780

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
			} else if (json_args.has("subscribe")) {
				json_output = subscribe(json_args);
				id = json_output.getString("id");
			} else if (json_args.has("remove")) {
				json_output = remove(json_args);
			} else if (json_args.has("share")) {
				json_output = share(json_args);
			}
			if (sslflag) {
				socketsendssl(sslsocket, json_output.toString());
			} else {
				output.writeUTF(json_output.toString());
				output.flush();
				log.log(Level.INFO, "[sent]:" + json_output.toString());
			}
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
								int fileSize = Integer.valueOf((String) command.get("resourceSize"));

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
			} else if (json_args.has("query")) {
				int k = 0;
				while (k < 20) {
					if (input.available() > 0) {
						String message = input.readUTF();
						log.log(Level.INFO, "[received]:" + message);
					}
					Thread.sleep(100);
					k++;
				}

			} else if (json_args.has("subscribe")) {
				Thread exit = new Thread(() -> exit_trigger(id, sslsocket, socket, sslflag));
				exit.setDaemon(true);
				exit.start();
				if (json_args.getBoolean("secure")) {
					BufferedReader in = new BufferedReader(new InputStreamReader(sslsocket.getInputStream()));
					// Read input from the client and print it to the screen
					String string = null;
					while (true) {
						string = in.readLine();
						if (string != null) {
							log.log(Level.INFO, "[received]: " + string);
						}
					}
				} else {
					while (true) {
						if (input.available() > 0) {
							String message = input.readUTF();
							log.log(Level.INFO, "[received]:" + message);
							System.out.println(message);
							System.out.println("press [enter] to exit");
						}
					}
				}
			} else if (sslflag) {
				while (true) {
					try {
						InputStream inputstream = sslsocket.getInputStream();
						InputStreamReader inputstreamreader = new InputStreamReader(inputstream);
						BufferedReader bufferedreader = new BufferedReader(inputstreamreader);
						String string = bufferedreader.readLine();
						if (string != null) {
							log.log(Level.INFO, "[received]:" + string);
							break;
						} else {
							Thread.sleep(200);
						}
					} catch (IOException e) {
					}
				}
			} else {
				while (true) {
					if (input.available() > 0) {
						log.log(Level.INFO, "receving:");
						String message = input.readUTF();
						log.log(Level.INFO, "[received]:" + message);
						break;
					} else {
						Thread.sleep(100);
					}
				}
			}
		} catch (UnknownHostException e) {
			log.log(Level.WARNING, e.toString());
			e.printStackTrace();
		} catch (IOException e) {
			log.log(Level.WARNING, e.toString());
			e.printStackTrace();
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			log.log(Level.WARNING, e.toString());
			e.printStackTrace();
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
		String publish_ezserver = "";
		ArrayList tagsList = null;
		String[] tagsArray = null;
		if (input.has("name"))
			publish_name = input.getString("name");
		if (input.has("tags")) {
			tagsArray = input.getString("tags").split(",");
			tagsList = new ArrayList<>(Arrays.asList(tagsArray));
		}
		if (input.has("description"))
			publish_description = input.getString("description");
		if (input.has("uri")) {
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
		resource.put("tags", tagsList);
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
		String[] tagsArray = null;
		ArrayList tagsList = null;
		String remove_description = "";
		String remove_uri = "";
		String remove_channel = "";
		String remove_owner = "";
		String remove_ezserver = null;

		if (input.has("name"))
			remove_name = input.getString("name");
		if (input.has("tags")) {
			tagsArray = input.getString("tags").split(",");
			tagsList = new ArrayList<>(Arrays.asList(tagsArray));
		}
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
		resource.put("tags", tagsList);
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
				String[] tagsArray = input.getString("tags").split(",");
				ArrayList tagsList = new ArrayList<>(Arrays.asList(tagsArray));
				output.put("tags", tagsList);
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
			tagsList = new ArrayList<>(Arrays.asList(tagsArray));
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
			tagsList = new ArrayList<>(Arrays.asList(tagsArray));
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
