package EZShare;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;

import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.RandomAccessFile;

import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

import CLI.cliserver;
import EZShare.resource;

import java.util.logging.Logger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Random;
//import java.util.concurrent.ExecutorService;
//import java.util.concurrent.Executors;

import org.json.*;
//import java.io.InputStream;

import java.util.logging.Level;

public class Server {
	private static final Logger log = Logger.getLogger(Server.class.getName());
	private static String secret = "abc";
	private static JSONArray ServerList = new JSONArray();
	private static JSONArray SSLServerList = new JSONArray();
	private static ArrayList<String> PublicChannel = new ArrayList<String>();
	private static ArrayList<resource> ResourcesList = new ArrayList<resource>();
	private static ArrayList<resource> ResourcesToPush = new ArrayList<resource>();
	private static JSONObject Channels = new JSONObject();
	private static int cil = 1;
	private static int eil = 600;
	private static int port = 3000;
	private static int sslport = 3781;
	private static JSONObject BlackList = new JSONObject();
	private static int MAXFILESIZE = 20 * 1024 * 1024;
	private static int TIMEOUT = 0;
	private static JSONObject SubscribeList = new JSONObject();
	private static JSONArray tamplateList = new JSONArray();
	private static JSONArray ssltamplateList = new JSONArray();
	// private static int MAXthread = 100;

	DataOutputStream output;

	public static ServerSocket linsten_socket(int port) {
		ServerSocketFactory factory = ServerSocketFactory.getDefault();
		ServerSocket server;
		try {
			server = factory.createServerSocket(port);
			log.log(Level.INFO, "socket listening on port " + port);
			return server;
		} catch (IOException e) {
			log.log(Level.SEVERE, e.toString());
			log.log(Level.SEVERE, "SECURE LISTENING ON  PORT FALIED PORT NUM:" + String.valueOf(port));
			System.exit(0);
			return null;
		}
	};

	public static SSLServerSocket linsten_sslsocket(int port) {
		// return a SSLServerSocket if success, or null if failed
		Path temp = null;
		try {
			temp = Files.createTempFile("server", ".jks1");
			Files.copy(Thread.currentThread().getContextClassLoader().getResourceAsStream("EZShare/server.jks"), temp,
					StandardCopyOption.REPLACE_EXISTING);
		} catch (IOException e2) {
			// TODO Auto-generated catch block
			e2.printStackTrace();
		}
		System.setProperty("javax.net.ssl.keyStore", temp.toString());
		System.setProperty("javax.net.ssl.keyStorePassword", "sdfjkl");

		try {
			temp = Files.createTempFile("client", ".jks1");
			Files.copy(Thread.currentThread().getContextClassLoader().getResourceAsStream("EZShare/client.jks"), temp,
					StandardCopyOption.REPLACE_EXISTING);
		} catch (IOException e2) {
			// TODO Auto-generated catch block
			e2.printStackTrace();
		}
		System.setProperty("javax.net.ssl.trustStore", temp.toString());
		try {
			SSLServerSocketFactory sslserversocketfactory = (SSLServerSocketFactory) SSLServerSocketFactory
					.getDefault();
			SSLServerSocket sslserversocket = (SSLServerSocket) sslserversocketfactory.createServerSocket(port);
			log.log(Level.INFO, "secure socket listening on port " + port);
			return sslserversocket;
		} catch (IOException e) {
			log.log(Level.SEVERE, e.toString());
			log.log(Level.SEVERE, "LISTENING ON  PORT FALIED PORT NUM:" + String.valueOf(port));
			System.exit(0);
			return null;
		}
	};

	// Identifies the user number connected
	public static JSONObject PutError(String message, JSONObject output) {
		output.put("response", "error");
		output.put("errorMessage", "missing or invalid server list");
		return output;
	}

	public static void set_args(JSONObject arg) {
		if (arg.getBoolean("debug"))
			log.setLevel(Level.ALL);
		else
			log.setLevel(Level.WARNING);
		port = arg.getInt("port");
		sslport = arg.getInt("sport");
		secret = arg.getString("secret");
		cil = arg.getInt("connectionintervallimit");
		eil = arg.getInt("exchangeinterval");
		String host = arg.getString("advertisedhostname");
		log.log(Level.INFO, "Start the EZShare Server");
		log.log(Level.INFO, "using advertised hostname: " + host);
		log.log(Level.INFO, "using secret: " + secret);
		log.log(Level.INFO, "Started");
		Channels.put("Public", PublicChannel);
	}

	public static void main(String[] args) {

		JSONObject arg = new cliserver(args).parse(log);
		set_args(arg);
		SSLServerSocket sslserversocket = linsten_sslsocket(sslport);
		ServerSocket serversocket = linsten_socket(port);

		// start thread to auto exchange
		Thread auto_ex = new Thread(() -> autoExchange(eil));
		auto_ex.setDaemon(true);
		auto_ex.start();

		Thread auto_sslex = new Thread(() -> autoSSLExchange(eil));
		auto_sslex.setDaemon(true);
		auto_sslex.start();

		// start thread to auto remove balcklist
		Thread auto_black = new Thread(() -> BlackListRemover(cil));
		auto_black.setDaemon(true);
		auto_black.start();

		// Wait for connections.
		Thread selecter = new Thread(() -> LISTEN(serversocket, log));
		Thread selecter_ssl = new Thread(() -> SSL_LISTEN(sslserversocket));
		selecter_ssl.setDaemon(true);
		selecter.setDaemon(true);
		selecter.start();
		selecter_ssl.start();

		Thread pusher = new Thread(() -> Pusher(100));
		pusher.setDaemon(true);
		pusher.start();

		try {
			Thread.sleep(1000 * 3600 * 24);
		} catch (InterruptedException e) {
			log.log(Level.SEVERE, e.toString());
			log.log(Level.INFO, "main class sleep  failed");
			return;
		}
	}

	private static void subscribe(resource newResource, JSONObject client_input, Socket client_socket) {
		JSONObject json_output = new JSONObject();
		String name = "";
		String description = "";
		ArrayList<String> tagsList = new ArrayList<String>();
		String URI = "";
		String channel = "";
		String owner = "";
		String EZserver = null;
		ArrayList<resource> matchResources = new ArrayList<resource>();
		int resultSize = 0;

		try {
			DataOutputStream output = new DataOutputStream(client_socket.getOutputStream());

			if (!client_input.has("resourceTemplate")) {
				json_output.put("response", "error");
				json_output.put("errorMessage", "missing resourceTemplate");
				output.writeUTF(json_output.toString());
				output.flush();

				log.log(Level.INFO, "message sent:" + json_output.toString());
			} else {
				JSONObject validTest = client_input.getJSONObject("resourceTemplate");
				resource re_tmp = new resource();

				if (validTest.has("tags")) {
					JSONArray JSON_tags = new JSONArray();
					JSON_tags = validTest.getJSONArray("tags");
					for (Object tag : JSON_tags) {
						tagsList.add(tag.toString());
					}
					if (!re_tmp.setTags(tagsList)) {
						invalid(json_output, output);
					}
				}
				if (!re_tmp.setName(validTest.getString("name"))) {
					invalid(json_output, output);
					return;
				} else {
					name = validTest.getString("name");
				}
				if (validTest.has("uri")) {
					URI = validTest.getString("uri").replace("\\/", "/");
				} else {
					invalid(json_output, output);
					return;
				}
				if (validTest.has("ezserver")) {
					if (!re_tmp.setZEserver(validTest.getString("ezserver"))) {
						invalid(json_output, output);
						return;
					} else {
						EZserver = validTest.getString("ezserver");
					}
				}
				if (!re_tmp.setDescription(validTest.getString("description"))) {
					invalid(json_output, output);
					return;
				} else {
					description = validTest.getString("description");
				}
				if (!re_tmp.setOwner(validTest.getString("owner"))) {
					invalid(json_output, output);
					return;
				} else {
					owner = validTest.getString("owner");
				}
				if (!re_tmp.setChannel(validTest.getString("channel"))) {
					invalid(json_output, output);
					return;
				} else {
					channel = validTest.getString("channel");
				}

			}

			// Check whether tags present in the template
			// also are present
			// in the candidate
			boolean tagsTest = true;
			if (tagsList != null) {
				for (int i = 0; i < tagsList.size(); i++) {
					boolean test = false;
					for (String tagInResourceR : newResource.getTags()) {
						if (tagsList.get(i).toLowerCase().equals(tagInResourceR.toLowerCase())) {
							test = true;
							break;
						}
					}
					if (test == false) {
						tagsTest = false;
						break;
					}
				}
			}
			// The candidate name contains the template name
			// as a substring
			// (for non "" template name)
			boolean nameTest;
			if (newResource.getName().contains(name) && !name.equals("")) {
				nameTest = true;
			} else {
				nameTest = false;
			}
			// The candidate description contains the
			// template description
			// as
			// a substring (for non "" template
			// descriptions)
			boolean desTest;
			if ((newResource.getDescription().contains(description) && !description.equals(""))
					|| newResource.getDescription().equals(description)) {
				desTest = true;
			} else {
				desTest = false;
			}
			// If the template contains an owner that is not
			// "", then the
			// candidate owner must equal it
			boolean ownerTest;
			if ((owner != "" && newResource.getOwner().equals(owner)) || owner.equals("")) {
				ownerTest = true;
			} else {
				ownerTest = false;
			}
			// The template channel equals (case sensitive)
			// the resource
			// channel
			boolean channelTest;
			if (newResource.getChannel().equals(channel)) {
				channelTest = true;
			} else {
				channelTest = false;
			}
			// If the template contains a URI then the
			// candidate URI matches
			// (case sensitive)
			boolean uriTest;
			if ((newResource.getURI().equals(URI) && !URI.equals("")) || URI.equals("")) {
				uriTest = true;
			} else {
				uriTest = false;
			}
			// Check QUERY success
			if (channelTest && ownerTest && tagsTest && uriTest
					&& (nameTest || desTest || (name.equals("") && description.equals("")))) {

				matchResources.add(newResource);
				resultSize++;
			}

			// output
			if (resultSize == 0) {
				json_output.put("response", "success");
				output.writeUTF(json_output.toString());
				output.flush();
				log.log(Level.INFO, "message sent:" + json_output.toString());

				JSONObject json_output2 = new JSONObject();
				json_output2.put("resultSize", 0);
				output.writeUTF(json_output2.toString());
				output.flush();
				log.log(Level.INFO, "message sent:" + json_output2.toString());
			} else {
				// Send message to client
				json_output.put("response", "success");
				output.writeUTF(json_output.toString());
				output.flush();
				log.log(Level.INFO, "message sent:" + json_output.toString());
				for (resource r : matchResources) {
					JSONObject json_outputResource = new JSONObject();
					json_outputResource.put("name", r.getName());
					json_outputResource.put("tags", r.getTags());
					json_outputResource.put("description", r.getDescription());
					json_outputResource.put("uri", r.getURI());
					json_outputResource.put("channel", r.getChannel());
					if (r.getOwner().equals("")) {
						json_outputResource.put("owner", "");
					} else {
						json_outputResource.put("owner", "*");
					}
					json_outputResource.put("ezserver", r.getEZserver());

					output.writeUTF(json_outputResource.toString());
					output.flush();
					log.log(Level.INFO, "message sent:" + json_outputResource.toString());
				}

				JSONObject json_outputFinal = new JSONObject();
				json_outputFinal.put("resultSize", resultSize);
				output.writeUTF(json_outputFinal.toString());
				output.flush();
				log.log(Level.INFO, "message sent:" + json_outputFinal.toString());

			}
		} catch (IOException e) {
			e.printStackTrace();
			log.log(Level.SEVERE, e.toString());
		}
	}

	private static void SSL_LISTEN(SSLServerSocket serversocket) {
		// ExecutorService SSLpool = Executors.newFixedThreadPool(MAXthread /
		// 2);
		while (true) {
			try {
				SSLSocket client = (SSLSocket) serversocket.accept();
				client.setKeepAlive(true);
				client.setSoTimeout(24 * 3600 * 1000);
				String client_address = client.getInetAddress().toString();
				if (!BlackList.has(client_address)) {
					BlackList.put(client_address, System.currentTimeMillis());
					// Start a new thread for a connection
					// SSLpool.execute(new SSLClientHandler(client, log));
					Thread t = new Thread(() -> sslserveClient(client, log));
					t.setDaemon(true);
					t.start();
				} else {
					client.close();
					log.log(Level.INFO, client_address + "blocked");
				}
			} catch (IOException e) {
				e.printStackTrace();
			}

		}
	}

	private static void LISTEN(ServerSocket serversocket, Logger log) {
		// ExecutorService pool = Executors.newFixedThreadPool(MAXthread / 2);
		while (true) {
			try {
				Socket client = (Socket) serversocket.accept();
				String client_address = client.getInetAddress().toString();
				if (!BlackList.has(client_address)) {
					BlackList.put(client_address, System.currentTimeMillis());
					// Start a new thread for a connection
					// pool.execute(new ClientHandler(client, log));
					Thread t = new Thread(() -> serveClient(client, log));
					t.setDaemon(true);
					t.start();
					log.log(Level.INFO, "one socket client");
				} else {
					client.close();
					log.log(Level.INFO, client_address + "blocked");
				}
			} catch (IOException e) {
				e.printStackTrace();
				return;
			}

		}
	}

	private static void BlackListRemover(int cli) {
		cli = cli * 1000;
		while (true) {
			// log.log(Level.INFO, "length of blacklist:" + BlackList.length());
			Long current_time = System.currentTimeMillis();
			Iterator<?> it = BlackList.keys();
			String key = "";
			while (it.hasNext()) {
				key = (String) it.next().toString();
				if ((long) BlackList.get(key) < current_time - cli) {
					BlackList.remove(key);
					log.log(Level.INFO, key + "removed from blacklist");
				}
			}
			try {
				Thread.sleep((int) (cli / 2));
			} catch (InterruptedException e) {
				log.log(Level.SEVERE, e.toString());
			}
		}
	}

	private static String StringCheck(String in) {
		// return modified String or throw an error
		try {
			in = in.trim();
			while (!((in.indexOf('\0') == -1))) {
				int index = in.indexOf('\0');
				in = in.substring(0, index) + in.substring(index + 1);
			}
			return in;
		} catch (Exception e) {
			log.log(Level.SEVERE, "StringCheck failed" + e.toString());
			throw e;
		}
	}

	private static JSONObject exchange(JSONObject input, Boolean sslflag) {
		JSONObject return_message = new JSONObject();
		JSONArray json_serverlist = (JSONArray) input.get("serverList");

		int i = 0;
		// empty list check
		if (0 >= json_serverlist.length()) {
			return_message = PutError("missing or invalid server list", return_message);
			return return_message;
		}

		while (i < json_serverlist.length()) {
			JSONObject json_server = (JSONObject) json_serverlist.get(i);
			try {
				String hostname = "";
				int port = 0;
				try {
					hostname = json_server.getString("hostname");
					port = json_server.getInt("port");
				} catch (Exception e) {
					return_message = PutError(e.toString(), return_message);
					log.log(Level.INFO, e.toString());
					return return_message;
				}

				if (hostname != null && (Object) port != null) {
					i++;
					if (i == json_serverlist.length()) {
						for (int k = 0; k < json_serverlist.length(); k++) {
							JSONObject temp = json_serverlist.getJSONObject(k);

							if (sslflag) {
								SSLServerList.put(temp);
							} else {
								ServerList.put(temp);
							}
						}
						return_message.put("response", "success");
					}
				} else {
					return_message = PutError("missing or invalid server list", return_message);
					return return_message;
				}

			} catch (Exception e) {
				log.log(Level.WARNING, e.toString());
				return_message = PutError("missing or invalid server list", return_message);
			}
		}
		return return_message;
	}

	private static JSONObject publish(JSONObject input) {
		log.log(Level.INFO, "length of resourcelist:" + ResourcesList.size());
		JSONObject output = new JSONObject();
		try {
			JSONObject inputJSON = input.getJSONObject("resource");

			// check uri
			resource tmp_re = new resource();
			if (!inputJSON.has("uri")) {
				output = PutError("invalid resource", output);
				return output;
			}
			String uri = inputJSON.getString("uri").replace("\\/", "/");
			// String uri = inputJSON.getString("uri").replace("\/", "/");
			if (uri.startsWith("file:")) {
				output.put("response", "error");
				output.put("errorMessage", "invalid resource");
				return output;
			}
			// set uri
			if (!tmp_re.setURI(uri, true)) {
				output.put("response", "error");
				output.put("errorMessage", "invalid resource");
				return output;
			}

			// check owner
			String owner = inputJSON.getString("owner");
			if (owner.equals("*")) {
				output.put("response", "error");
				output.put("errorMessage", "invalid resource");
				return output;
			}
			// set owner
			if (!tmp_re.setOwner(owner)) {
				output.put("response", "error");
				output.put("errorMessage", "invalid resource");
				return output;
			}
			// check channel
			String channel = inputJSON.optString("channel", "");
			if (!tmp_re.setChannel(channel)) {
				output.put("response", "error");
				output.put("errorMessage", "invalid resource");
				return output;
			}

			String[] current_key = tmp_re.getKey();
			ArrayList<String> tags = new ArrayList<String>();
			resource ToRemove = null;
			for (resource r : ResourcesList) {
				String[] tmp_key = r.getKey();
				log.log(Level.INFO, tmp_key[1] + "," + current_key[1] + ";" + tmp_key[2] + "," + current_key[2] + ";"
						+ tmp_key[0] + "," + tmp_key[0]);
				if (tmp_key[1].equals(current_key[1]) && tmp_key[2].equals(current_key[2])
						&& !tmp_key[0].equals(current_key[0])) {
					output.put("response", "error");
					output.put("errorMessage", "cannot publish resource");
					return output;
				}
				if (StringListSame(tmp_key, current_key)) {
					ToRemove = r;
				}

			}
			if (!(ToRemove == null)) {
				ResourcesList.remove(ResourcesList.indexOf(ToRemove));
				log.log(Level.WARNING, "resource removed:" + ToRemove.getKey().toString());
			}
			if (!tmp_re.setName(inputJSON.optString("name", ""))) {
				log.log(Level.INFO, "invalid name");
				output.put("response", "error");
				output.put("errorMessage", "invalid resource");
				return output;
			}

			if (inputJSON.has("tags")) {
				JSONArray JSON_tags = new JSONArray();
				JSON_tags = inputJSON.getJSONArray("tags");
				for (Object tag : JSON_tags)
					tags.add(tag.toString());
			}
			if (!tmp_re.setTags(tags)) {
				log.log(Level.INFO, "invalid tags");
				output.put("response", "error");
				output.put("errorMessage", "invalid resource");
				return output;
			}

			if (!tmp_re.setZEserver(inputJSON.optString("ezserver"))) {
				log.log(Level.INFO, "invalid ezserver");
				output.put("response", "error");
				output.put("errorMessage", "invalid resource");
				return output;
			}
			if (!tmp_re.setDescription(inputJSON.optString("description"))) {
				log.log(Level.INFO, "invalid description");
				output.put("response", "error");
				output.put("errorMessage", "invalid resource");
				return output;
			}

			ResourcesList.add(tmp_re);
			ResourcesToPush.add(tmp_re);
			log.log(Level.INFO, "resource added");
			output.put("response", "success");
			return output;
		} catch (Exception e) {
			log.log(Level.WARNING, "error when setting value" + e.toString());
			output.put("response", "error");
			output.put("errorMessage", "invalid resource");
			return output;
		}
		// check the resource field

	}

	private static JSONObject remove(JSONObject input) {
		log.log(Level.INFO, "before:" + ResourcesList.size());
		JSONObject output = new JSONObject();
		String uri = null;
		String channel = null;
		String owner = null;
		try {
			JSONObject json_Resource = input.getJSONObject("resource");
			uri = StringCheck(json_Resource.getString("uri").replace("\\/", "/"));
			channel = StringCheck(json_Resource.optString("channel", ""));
			owner = StringCheck(json_Resource.optString("owner", ""));
			if (uri.equals("")) {
				log.log(Level.INFO, "incorrect information");
				output.put("response", "error");
				output.put("errorMessage", "invalid resource");
			}
		} catch (Exception e) {
			log.log(Level.INFO, "missing resource:" + e.toString());
			output.put("response", "error");
			output.put("errorMessage", "invalid resource");
		}
		// check resource exit
		String[] current_key = { owner, channel, uri };
		for (resource tmp : ResourcesList) {
			try {
				if (StringListSame(tmp.getKey(), current_key)) {
					ResourcesList.remove(tmp);
					try {
						log.log(Level.WARNING,
								"resource removed:" + tmp.getKey()[0] + "," + tmp.getKey()[1] + "," + tmp.getKey()[2]);
					} catch (Exception e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					output.put("response", "success");
					return output;
				}
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		output.put("response", "error");
		output.put("errorMessage", "cannot remove resource");
		return output;
	}

	private static Boolean StringListSame(String[] a, String[] b) {
		if (!(a.length == b.length))
			return false;
		for (int i = 0; i < a.length; i++) {
			if (!(a[i].equals(b[i])))
				return false;
		}
		return true;
	}

	private static void RelayReader(Socket client, Logger log) {
		while (true) {
			String rea = read(client);
			resource re = JSONtoResource(new JSONObject(rea));
			ResourcesToPush.add(re);
		}

	}
	private static void RelayReaderSSL(SSLSocket client, Logger log) {
		while (true) {
			String rea = readssl(client,log);
			resource re = JSONtoResource(new JSONObject(rea));
			ResourcesToPush.add(re);
		}

	}

	private static void Pusher(int time) {
		int size = ResourcesToPush.size();
		while (true) {
			if (size != ResourcesToPush.size()) {
				log.log(Level.INFO, "length of topush:" + String.valueOf(ResourcesToPush.size()));
				size = ResourcesToPush.size();
			}
			if (!ResourcesToPush.isEmpty()) {
				for (int i = 0; i < ResourcesToPush.size(); i++) {
					resource r = ResourcesToPush.get(i);
					Iterator it = SubscribeList.keys();
					while (it.hasNext()) {
						String key = (String) it.next();
						JSONObject json_client = (JSONObject) SubscribeList.get(key);
						JSONObject clientInput = (JSONObject) json_client.get("client_input");
						String connection = json_client.getString("connection_type");
						Boolean sslflag = true;
						if (connection == "socket")
							sslflag = false;
						JSONObject json_output = new JSONObject();
						String qname = "";
						String qdescription = "";
						// String[] qtagsArray = null;
						ArrayList<String> qtagsList = new ArrayList<String>();
						String qURI = "";
						String qchannel = "";
						String qowner = "";
						String qEZserver = null;
						ArrayList<resource> matchResources = new ArrayList<resource>();
						JSONObject validTest = clientInput.getJSONObject("resourceTemplate");
						resource re_tmp = new resource();
						if (validTest.has("tags")) {
							JSONArray JSON_tags = new JSONArray();
							JSON_tags = validTest.getJSONArray("tags");
							for (Object tag : JSON_tags) {
								qtagsList.add(tag.toString());
							}
							if (!re_tmp.setTags(qtagsList)) {
							}
						}
						if (!re_tmp.setName(validTest.getString("name"))) {
							log.log(Level.WARNING, "match failed");
							return;
						} else {
							qname = validTest.getString("name");
						}
						if (validTest.has("uri")) {
							qURI = validTest.getString("uri").replace("\\/", "/");
						} else {
							log.log(Level.WARNING, "match failed");
							return;
						}
						if (validTest.has("ezserver")) {
							if (!re_tmp.setZEserver(validTest.getString("ezserver"))) {
								log.log(Level.WARNING, "match failed");
								return;
							} else {
								qEZserver = validTest.getString("ezserver");
							}
						}
						if (!re_tmp.setDescription(validTest.getString("description"))) {
							log.log(Level.WARNING, "match failed");
							return;
						} else {
							qdescription = validTest.getString("description");
						}
						if (!re_tmp.setOwner(validTest.getString("owner"))) {
							log.log(Level.WARNING, "match failed");
							return;
						} else {
							qowner = validTest.getString("owner");
						}
						if (!re_tmp.setChannel(validTest.getString("channel"))) {
							log.log(Level.WARNING, "match failed");
							return;
						} else {
							qchannel = validTest.getString("channel");
						}

						// matching
						boolean tagsTest = true;
						if (qtagsList != null) {
							for (int k = 0; k < qtagsList.size(); k++) {
								boolean test = false;
								for (String tagInResourceR : r.getTags()) {
									if (qtagsList.get(k).toLowerCase().equals(tagInResourceR.toLowerCase())) {
										test = true;
										break;
									}
								}
								if (test == false) {
									tagsTest = false;
									break;
								}
							}
						}
						// The candidate name contains the template name as a
						// substring
						// (for non "" template name)
						boolean nameTest;
						if (r.getName().contains(qname) && !qname.equals("")) {
							nameTest = true;
						} else {
							nameTest = false;
						}
						// The candidate description contains the template
						// description
						// as
						// a substring (for non "" template descriptions)
						boolean desTest;
						if ((r.getDescription().contains(qdescription) && !qdescription.equals(""))
								|| r.getDescription().equals(qdescription)) {
							desTest = true;
						} else {
							desTest = false;
						}
						// If the template contains an owner that is not "",
						// then the
						// candidate owner must equal it
						boolean ownerTest;
						if ((qowner != "" && r.getOwner().equals(qowner)) || qowner.equals("")) {
							ownerTest = true;
						} else {
							ownerTest = false;
						}
						// The template channel equals (case sensitive) the
						// resource
						// channel
						boolean channelTest;
						if (r.getChannel().equals(qchannel)) {
							channelTest = true;
						} else {
							channelTest = false;
						}
						// If the template contains a URI then the candidate URI
						// matches
						// (case sensitive)
						boolean uriTest;
						if ((r.getURI().equals(qURI) && !qURI.equals("")) || qURI.equals("")) {
							uriTest = true;
						} else {
							uriTest = false;
						}
						// Check QUERY success
						if (channelTest && ownerTest && tagsTest && uriTest
								&& (nameTest || desTest || (qname.equals("") && qdescription.equals("")))) {
							JSONObject json_outputResource = new JSONObject();
							json_outputResource.put("name", r.getName());
							json_outputResource.put("tags", r.getTags());
							json_outputResource.put("description", r.getDescription());
							json_outputResource.put("uri", r.getURI());
							json_outputResource.put("channel", r.getChannel());
							if (r.getOwner().equals("")) {
								json_outputResource.put("owner", "");
							} else {
								json_outputResource.put("owner", "*");
							}
							json_outputResource.put("ezserver", r.getEZserver());

							if (sslflag) {
								SSLSocket ssl = (SSLSocket) json_client.get("connection");
								try {
									ssl.setKeepAlive(true);
								} catch (SocketException e) {
									// TODO Auto-generated catch block
									e.printStackTrace();
								}
								log.log(Level.SEVERE, String.valueOf(ssl.isClosed()));
								socketsendssl(ssl, json_outputResource.toString());
							} else {
								socketsend((Socket) json_client.get("connection"), json_outputResource.toString());
							}
							int count = json_client.getInt("count");
							count = count + 1;
							json_client.put("count", count);
						}

					}
				}
				ResourcesToPush = new ArrayList<resource>();
			}

			else {
				// for (){}
				try {
					Thread.sleep(time);
				} catch (InterruptedException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}

	}

	private static JSONObject share(JSONObject input) {
		JSONObject output = new JSONObject();
		ArrayList<String> string_tags = new ArrayList<String>();
		try {
			if (!input.has("resource")) {
				output.put("response", "error");
				output.put("errorMessage", "missing resource and/or secret");
				return output;
			}
			JSONObject resource_json = input.getJSONObject("resource");
			String uri = resource_json.optString("uri", "").replace("\\/", "/");
			String input_secret = "";
			JSONArray tags = new JSONArray();

			if (resource_json.has("tags")) {
				tags = resource_json.getJSONArray("tags");
			}
			for (Object tag : tags) {
				string_tags.add(tag.toString());
			}
			// checking inputs
			if (input.has("secret")) {
				input_secret = input.getString("secret");
			} else {
				output.put("response", "error");
				output.put("errorMessage", "missing resource and/or secret");
				return output;
			}
			if (input_secret.equals("")) {
				output.put("response", "error");
				output.put("errorMessage", "missing resource and/or secret");
				return output;
			}
			if (!input_secret.equals(secret)) {
				output.put("response", "error");
				output.put("errorMessage", "incorrect secret");
				output.put("secret", secret);
				return output;
			}
			if (!(uri.substring(0, 5).equals("file:"))) {
				output.put("response", "error");
				output.put("errorMessage", "invalid resource");
				return output;
			}
			// insert value to temp
			resource re_tmp = new resource();
			if (!re_tmp.setName(resource_json.optString("name", ""))) {
				output.put("response", "error");
				output.put("errorMessage", "invalid resource");
				return output;
			}
			if (!re_tmp.setTags(string_tags)) {
				output.put("response", "error");
				output.put("errorMessage", "invalid resource");
				return output;
			}
			if (!re_tmp.setURI(uri, false)) {
				output.put("response", "error");
				output.put("errorMessage", "cannot share resource");
				return output;
			}
			if (!re_tmp.setZEserver(resource_json.optString("ezserver"))) {
				output.put("response", "error");
				output.put("errorMessage", "invalid resource");
				return output;
			}
			if (!re_tmp.setDescription(resource_json.optString("description"))) {
				output.put("response", "error");
				output.put("errorMessage", "invalid resource");
				return output;
			}
			if (!re_tmp.setOwner(resource_json.optString("owner"))) {
				output.put("response", "error");
				output.put("errorMessage", "invalid resource");
				return output;
			}
			if (!re_tmp.setChannel(resource_json.optString("channel"))) {
				output.put("response", "error");
				output.put("errorMessage", "invalid resource");
				return output;
			}

			// primary key check
			String[] current_key = re_tmp.getKey();
			resource to_remove = null;
			for (int index = 0; index < ResourcesList.size(); index++) {
				resource tmp = ResourcesList.get(index);
				String[] tmp_key = tmp.getKey();
				if (tmp_key[1].equals(current_key[1]) && tmp_key[2].equals(current_key[2])
						&& !tmp_key[0].equals(current_key[0])) {
					output.put("response", "error");
					output.put("errorMessage", "cannot share resource");
					return output;
				}
				if (StringListSame(tmp_key, current_key)) {
					to_remove = tmp;
					break;
				}
			}
			if (!(to_remove == null)) {
				ResourcesList.remove(ResourcesList.indexOf(to_remove));
				log.log(Level.WARNING, "resource removed:" + to_remove.getKey()[0] + "," + to_remove.getKey()[1] + ","
						+ to_remove.getKey()[2]);
			}
			ResourcesList.add(re_tmp);
			ResourcesToPush.add(re_tmp);
			output.put("response", "success");
			return output;
		} catch (Exception e) {
			output.put("response", "error");
			output.put("errorMessage", "missing or invalid resource");
			log.log(Level.WARNING, e.toString());
			return output;
		}
	}

	private static void query(JSONObject input, Socket client) {
		JSONObject json_output = new JSONObject();
		String qname = "";
		String qdescription = "";
		// String[] qtagsArray = null;
		ArrayList<String> qtagsList = new ArrayList<String>();
		String qURI = "";
		String qchannel = "";
		String qowner = "";
		String qEZserver = null;
		ArrayList<resource> matchResources = new ArrayList<resource>();
		int resultSize = 0;

		try {
			DataOutputStream output = new DataOutputStream(client.getOutputStream());

			if (!input.has("resourceTemplate")) {
				json_output.put("response", "error");
				json_output.put("errorMessage", "missing resourceTemplate");
				output.writeUTF(json_output.toString());
				output.flush();

				log.log(Level.INFO, "message sent:" + json_output.toString());
			} else {
				JSONObject validTest = input.getJSONObject("resourceTemplate");
				resource re_tmp = new resource();

				if (validTest.has("tags")) {
					JSONArray JSON_tags = new JSONArray();
					JSON_tags = validTest.getJSONArray("tags");
					for (Object tag : JSON_tags) {
						qtagsList.add(tag.toString());
					}
					if (!re_tmp.setTags(qtagsList)) {
						invalid(json_output, output);
					}
				}
				if (!re_tmp.setName(validTest.getString("name"))) {
					invalid(json_output, output);
					return;
				} else {
					qname = validTest.getString("name");
				}
				if (validTest.has("uri")) {
					qURI = validTest.getString("uri").replace("\\/", "/");
				} else {
					invalid(json_output, output);
					return;
				}
				if (validTest.has("ezserver")) {
					if (!re_tmp.setZEserver(validTest.getString("ezserver"))) {
						invalid(json_output, output);
						return;
					} else {
						qEZserver = validTest.getString("ezserver");
					}
				}
				if (!re_tmp.setDescription(validTest.getString("description"))) {
					invalid(json_output, output);
					return;
				} else {
					qdescription = validTest.getString("description");
				}
				if (!re_tmp.setOwner(validTest.getString("owner"))) {
					invalid(json_output, output);
					return;
				} else {
					qowner = validTest.getString("owner");
				}
				if (!re_tmp.setChannel(validTest.getString("channel"))) {
					invalid(json_output, output);
					return;
				} else {
					qchannel = validTest.getString("channel");
				}

			}

			for (resource r : ResourcesList) {
				// Check whether tags present in the template also are present
				// in the candidate
				boolean tagsTest = true;
				if (qtagsList != null) {
					for (int i = 0; i < qtagsList.size(); i++) {
						boolean test = false;
						for (String tagInResourceR : r.getTags()) {
							if (qtagsList.get(i).toLowerCase().equals(tagInResourceR.toLowerCase())) {
								test = true;
								break;
							}
						}
						if (test == false) {
							tagsTest = false;
							break;
						}
					}
				}
				// The candidate name contains the template name as a substring
				// (for non "" template name)
				boolean nameTest;
				if (r.getName().contains(qname) && !qname.equals("")) {
					nameTest = true;
				} else {
					nameTest = false;
				}
				// The candidate description contains the template description
				// as
				// a substring (for non "" template descriptions)
				boolean desTest;
				if ((r.getDescription().contains(qdescription) && !qdescription.equals(""))
						|| r.getDescription().equals(qdescription)) {
					desTest = true;
				} else {
					desTest = false;
				}
				// If the template contains an owner that is not "", then the
				// candidate owner must equal it
				boolean ownerTest;
				if ((qowner != "" && r.getOwner().equals(qowner)) || qowner.equals("")) {
					ownerTest = true;
				} else {
					ownerTest = false;
				}
				// The template channel equals (case sensitive) the resource
				// channel
				boolean channelTest;
				if (r.getChannel().equals(qchannel)) {
					channelTest = true;
				} else {
					channelTest = false;
				}
				// If the template contains a URI then the candidate URI matches
				// (case sensitive)
				boolean uriTest;
				if ((r.getURI().equals(qURI) && !qURI.equals("")) || qURI.equals("")) {
					uriTest = true;
				} else {
					uriTest = false;
				}
				// Check QUERY success
				if (channelTest && ownerTest && tagsTest && uriTest
						&& (nameTest || desTest || (qname.equals("") && qdescription.equals("")))) {

					matchResources.add(r);
					resultSize++;
				}

			}
			// output
			if (resultSize == 0) {
				json_output.put("response", "success");
				output.writeUTF(json_output.toString());
				output.flush();
				log.log(Level.INFO, "message sent:" + json_output.toString());

				JSONObject json_output2 = new JSONObject();
				json_output2.put("resultSize", 0);
				output.writeUTF(json_output2.toString());
				output.flush();
				log.log(Level.INFO, "message sent:" + json_output2.toString());
			} else {
				// Send message to client
				json_output.put("response", "success");
				output.writeUTF(json_output.toString());
				output.flush();
				log.log(Level.INFO, "message sent:" + json_output.toString());
				for (resource r : matchResources) {
					JSONObject json_outputResource = new JSONObject();
					json_outputResource.put("name", r.getName());
					json_outputResource.put("tags", r.getTags());
					json_outputResource.put("description", r.getDescription());
					json_outputResource.put("uri", r.getURI());
					json_outputResource.put("channel", r.getChannel());
					if (r.getOwner().equals("")) {
						json_outputResource.put("owner", "");
					} else {
						json_outputResource.put("owner", "*");
					}
					json_outputResource.put("ezserver", r.getEZserver());

					output.writeUTF(json_outputResource.toString());
					output.flush();
					log.log(Level.INFO, "[sent]:" + json_outputResource.toString());
				}

				JSONObject json_outputFinal = new JSONObject();
				json_outputFinal.put("resultSize", resultSize);
				output.writeUTF(json_outputFinal.toString());
				output.flush();
				log.log(Level.INFO, "[sent]:" + json_outputFinal.toString());
				client.close();
			}
		} catch (IOException e) {
			e.printStackTrace();
			log.log(Level.SEVERE, e.toString());
		}
	}

	private static void queryssl(JSONObject input, SSLSocket client) {
		try {
			client.setKeepAlive(true);
		} catch (SocketException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		JSONObject json_output = new JSONObject();
		String qname = "";
		String qdescription = "";
		// String[] qtagsArray = null;
		ArrayList<String> qtagsList = new ArrayList<String>();
		String qURI = "";
		String qchannel = "";
		String qowner = "";
		String qEZserver = null;
		ArrayList<resource> matchResources = new ArrayList<resource>();
		int resultSize = 0;

		try {
			DataOutputStream output = new DataOutputStream(client.getOutputStream());

			if (!input.has("resourceTemplate")) {
				json_output.put("response", "error");
				json_output.put("errorMessage", "missing resourceTemplate");
				output.writeUTF(json_output.toString());
				output.flush();

				log.log(Level.INFO, "message sent:" + json_output.toString());
			} else {
				JSONObject validTest = input.getJSONObject("resourceTemplate");
				resource re_tmp = new resource();

				if (validTest.has("tags")) {
					JSONArray JSON_tags = new JSONArray();
					JSON_tags = validTest.getJSONArray("tags");
					for (Object tag : JSON_tags) {
						qtagsList.add(tag.toString());
					}
					if (!re_tmp.setTags(qtagsList)) {
						invalid(json_output, output);
					}
				}
				if (!re_tmp.setName(validTest.getString("name"))) {
					invalid(json_output, output);
					return;
				} else {
					qname = validTest.getString("name");
				}
				if (validTest.has("uri")) {
					qURI = validTest.getString("uri").replace("\\/", "/");
				} else {
					invalid(json_output, output);
					return;
				}
				if (validTest.has("ezserver")) {
					if (!re_tmp.setZEserver(validTest.getString("ezserver"))) {
						invalid(json_output, output);
						return;
					} else {
						qEZserver = validTest.getString("ezserver");
					}
				}
				if (!re_tmp.setDescription(validTest.getString("description"))) {
					invalid(json_output, output);
					return;
				} else {
					qdescription = validTest.getString("description");
				}
				if (!re_tmp.setOwner(validTest.getString("owner"))) {
					invalid(json_output, output);
					return;
				} else {
					qowner = validTest.getString("owner");
				}
				if (!re_tmp.setChannel(validTest.getString("channel"))) {
					invalid(json_output, output);
					return;
				} else {
					qchannel = validTest.getString("channel");
				}

			}

			for (resource r : ResourcesList) {
				// Check whether tags present in the template also are present
				// in the candidate
				boolean tagsTest = true;
				if (qtagsList != null) {
					for (int i = 0; i < qtagsList.size(); i++) {
						boolean test = false;
						for (String tagInResourceR : r.getTags()) {
							if (qtagsList.get(i).toLowerCase().equals(tagInResourceR.toLowerCase())) {
								test = true;
								break;
							}
						}
						if (test == false) {
							tagsTest = false;
							break;
						}
					}
				}
				// The candidate name contains the template name as a substring
				// (for non "" template name)
				boolean nameTest;
				if (r.getName().contains(qname) && !qname.equals("")) {
					nameTest = true;
				} else {
					nameTest = false;
				}
				// The candidate description contains the template description
				// as
				// a substring (for non "" template descriptions)
				boolean desTest;
				if ((r.getDescription().contains(qdescription) && !qdescription.equals(""))
						|| r.getDescription().equals(qdescription)) {
					desTest = true;
				} else {
					desTest = false;
				}
				// If the template contains an owner that is not "", then the
				// candidate owner must equal it
				boolean ownerTest;
				if ((qowner != "" && r.getOwner().equals(qowner)) || qowner.equals("")) {
					ownerTest = true;
				} else {
					ownerTest = false;
				}
				// The template channel equals (case sensitive) the resource
				// channel
				boolean channelTest;
				if (r.getChannel().equals(qchannel)) {
					channelTest = true;
				} else {
					channelTest = false;
				}
				// If the template contains a URI then the candidate URI matches
				// (case sensitive)
				boolean uriTest;
				if ((r.getURI().equals(qURI) && !qURI.equals("")) || qURI.equals("")) {
					uriTest = true;
				} else {
					uriTest = false;
				}
				// Check QUERY success
				if (channelTest && ownerTest && tagsTest && uriTest
						&& (nameTest || desTest || (qname.equals("") && qdescription.equals("")))) {

					matchResources.add(r);
					resultSize++;
				}

			}
			// output
			if (resultSize == 0) {
				json_output.put("response", "success");
				output.writeUTF(json_output.toString());
				output.flush();
				log.log(Level.INFO, "message sent:" + json_output.toString());

				JSONObject json_output2 = new JSONObject();
				json_output2.put("resultSize", 0);
				output.writeUTF(json_output2.toString());
				output.flush();
				log.log(Level.INFO, "message sent:" + json_output2.toString());
			} else {
				// Send message to client
				json_output.put("response", "success");
				output.writeUTF(json_output.toString());
				output.flush();
				log.log(Level.INFO, "message sent:" + json_output.toString());
				for (resource r : matchResources) {
					JSONObject json_outputResource = new JSONObject();
					json_outputResource.put("name", r.getName());
					json_outputResource.put("tags", r.getTags());
					json_outputResource.put("description", r.getDescription());
					json_outputResource.put("uri", r.getURI());
					json_outputResource.put("channel", r.getChannel());
					if (r.getOwner().equals("")) {
						json_outputResource.put("owner", "");
					} else {
						json_outputResource.put("owner", "*");
					}
					json_outputResource.put("ezserver", r.getEZserver());

					output.writeUTF(json_outputResource.toString());
					output.flush();
					log.log(Level.INFO, "message sent:" + json_outputResource.toString());
				}

				JSONObject json_outputFinal = new JSONObject();
				json_outputFinal.put("resultSize", resultSize);
				output.writeUTF(json_outputFinal.toString());
				output.flush();
				log.log(Level.INFO, "message sent:" + json_outputFinal.toString());
				client.close();
			}
		} catch (IOException e) {
			e.printStackTrace();
			log.log(Level.SEVERE, e.toString());
		}
	}

	private static void fetchssl(JSONObject input, SSLSocket client) {
		try {
			client.setKeepAlive(true);
		} catch (SocketException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		JSONObject json_output = new JSONObject();
		String fURI = "";
		String fchannel = "";
		ArrayList<String> ftagsList = new ArrayList<String>();
		resource fetchResource = new resource();

		try {
			DataOutputStream output = new DataOutputStream(client.getOutputStream());

			if (!input.has("resourceTemplate")) {
				json_output.put("response", "error");
				json_output.put("errorMessage", "missing resourceTemplate");
				output.writeUTF(json_output.toString());
				output.flush();
				log.log(Level.INFO, "message sent:" + json_output.toString());
			} else {
				JSONObject validTest = input.getJSONObject("resourceTemplate");
				resource re_tmp = new resource();

				if (validTest.has("tags")) {
					JSONArray JSON_tags = new JSONArray();
					JSON_tags = validTest.getJSONArray("tags");
					for (Object tag : JSON_tags) {
						ftagsList.add(tag.toString());
					}
					if (!re_tmp.setTags(ftagsList)) {
						invalid(json_output, output);
					}
				}
				if (!re_tmp.setName(validTest.getString("name"))) {
					invalid(json_output, output);
				}
				if (validTest.has("uri")) {
					fURI = validTest.getString("uri").replace("\\/", "/");
				}
				if (validTest.has("ezserver")) {
					if (!re_tmp.setZEserver(validTest.getString("ezserver"))) {
						invalid(json_output, output);
					}
				}
				if (!re_tmp.setDescription(validTest.getString("description"))) {
					invalid(json_output, output);
				}
				if (!re_tmp.setOwner(validTest.getString("owner"))) {
					invalid(json_output, output);
				}
				if (!re_tmp.setChannel(validTest.getString("channel"))) {
					invalid(json_output, output);
				} else {
					fchannel = validTest.getString("channel");
				}
			}

			boolean resourceExist = false;
			// Check resources' URI and channel
			for (resource r : ResourcesList) {
				if (r.getChannel().equals(fchannel) && r.getURI().equals(fURI)) {
					fetchResource = r;
					resourceExist = true;
				}
			}

			// output
			if (resourceExist == false) {
				json_output.put("response", "success");
				output.writeUTF(json_output.toString());
				output.flush();
				log.log(Level.INFO, "message sent:" + json_output.toString());
				JSONObject json_output2 = new JSONObject();
				json_output2.put("resultSize", 0);
				output.writeUTF(json_output2.toString());
				output.flush();
				log.log(Level.INFO, "message sent:" + json_output2.toString());
			} else {
				// Send message to client
				json_output.put("response", "success");
				json_output.put("uri", fURI);
				output.writeUTF(json_output.toString());
				output.flush();
				log.log(Level.INFO, "message sent:" + json_output.toString());

				// Check if file exists
				String fURInew = fURI.replace("\\", "").substring(8);
				File f = new File(fURInew);
				long fileSize = f.length();
				if (f.exists()) {

					// Send this back to client so that they know what the file
					// is.
					JSONObject fetchResult = new JSONObject();
					// trigger = serverResponse.fetchResponse(f.length(),
					// fetchResource);
					fetchResult.put("name", fetchResource.getName());
					fetchResult.put("tags", fetchResource.getTags());
					fetchResult.put("description", fetchResource.getDescription());
					fetchResult.put("uri", fetchResource.getURI());
					fetchResult.put("channel", fetchResource.getChannel());
					if (fetchResource.getOwner().equals("")) {
						fetchResult.put("owner", "");
					} else {
						fetchResult.put("owner", "*");
					}
					fetchResult.put("ezserver", fetchResource.getEZserver());
					fetchResult.put("resourceSize", fileSize);
					output.writeUTF(fetchResult.toString());
					output.flush();
					log.log(Level.INFO, "message sent:" + json_output.toString());

					try {
						// Start sending file
						// JSONObject sendingFile = new JSONObject();
						RandomAccessFile byteFile = new RandomAccessFile(f, "r");
						byte[] sendingBuffer = new byte[MAXFILESIZE];
						int num;
						// While there are still bytes to send..
						while ((num = byteFile.read(sendingBuffer)) > 0) {
							output.write(Arrays.copyOf(sendingBuffer, num));
						}
						byteFile.close();
					} catch (IOException e) {
						e.printStackTrace();
					}
					JSONObject json_output2 = new JSONObject();
					json_output2.put("resultSize", 1);
					output.writeUTF(json_output2.toString());
					output.flush();
					client.close();
					log.log(Level.INFO, "message sent:" + json_output2.toString());
				} else {
					log.log(Level.SEVERE, "error:" + "file cannot be read!");
				}
			}

		} catch (IOException e) {
			e.printStackTrace();
			log.log(Level.SEVERE, e.toString());
		}

	}

	private static void fetch(JSONObject input, Socket client) {
		JSONObject json_output = new JSONObject();
		String fURI = "";
		String fchannel = "";
		ArrayList<String> ftagsList = new ArrayList<String>();
		resource fetchResource = new resource();

		try {
			DataOutputStream output = new DataOutputStream(client.getOutputStream());

			if (!input.has("resourceTemplate")) {
				json_output.put("response", "error");
				json_output.put("errorMessage", "missing resourceTemplate");
				output.writeUTF(json_output.toString());
				output.flush();
				log.log(Level.INFO, "message sent:" + json_output.toString());
			} else {
				JSONObject validTest = input.getJSONObject("resourceTemplate");
				resource re_tmp = new resource();

				if (validTest.has("tags")) {
					JSONArray JSON_tags = new JSONArray();
					JSON_tags = validTest.getJSONArray("tags");
					for (Object tag : JSON_tags) {
						ftagsList.add(tag.toString());
					}
					if (!re_tmp.setTags(ftagsList)) {
						invalid(json_output, output);
					}
				}
				if (!re_tmp.setName(validTest.getString("name"))) {
					invalid(json_output, output);
				}
				if (validTest.has("uri")) {
					fURI = validTest.getString("uri").replace("\\/", "/");
				}
				if (validTest.has("ezserver")) {
					if (!re_tmp.setZEserver(validTest.getString("ezserver"))) {
						invalid(json_output, output);
					}
				}
				if (!re_tmp.setDescription(validTest.getString("description"))) {
					invalid(json_output, output);
				}
				if (!re_tmp.setOwner(validTest.getString("owner"))) {
					invalid(json_output, output);
				}
				if (!re_tmp.setChannel(validTest.getString("channel"))) {
					invalid(json_output, output);
				} else {
					fchannel = validTest.getString("channel");
				}
			}

			boolean resourceExist = false;
			// Check resources' URI and channel
			for (resource r : ResourcesList) {
				if (r.getChannel().equals(fchannel) && r.getURI().equals(fURI)) {
					fetchResource = r;
					resourceExist = true;
				}
			}

			// output
			if (resourceExist == false) {
				json_output.put("response", "success");
				output.writeUTF(json_output.toString());
				output.flush();
				log.log(Level.INFO, "message sent:" + json_output.toString());
				JSONObject json_output2 = new JSONObject();
				json_output2.put("resultSize", 0);
				output.writeUTF(json_output2.toString());
				output.flush();
				log.log(Level.INFO, "message sent:" + json_output2.toString());
			} else {
				// Send message to client
				json_output.put("response", "success");
				json_output.put("uri", fURI);
				output.writeUTF(json_output.toString());
				output.flush();
				log.log(Level.INFO, "message sent:" + json_output.toString());

				// Check if file exists
				String fURInew = fURI.replace("\\", "").substring(8);
				File f = new File(fURInew);
				long fileSize = f.length();
				if (f.exists()) {

					// Send this back to client so that they know what the file
					// is.
					JSONObject fetchResult = new JSONObject();
					// trigger = serverResponse.fetchResponse(f.length(),
					// fetchResource);
					fetchResult.put("name", fetchResource.getName());
					fetchResult.put("tags", fetchResource.getTags());
					fetchResult.put("description", fetchResource.getDescription());
					fetchResult.put("uri", fetchResource.getURI());
					fetchResult.put("channel", fetchResource.getChannel());
					if (fetchResource.getOwner().equals("")) {
						fetchResult.put("owner", "");
					} else {
						fetchResult.put("owner", "*");
					}
					fetchResult.put("ezserver", fetchResource.getEZserver());
					fetchResult.put("resourceSize", fileSize);
					output.writeUTF(fetchResult.toString());
					output.flush();
					log.log(Level.INFO, "message sent:" + json_output.toString());

					try {
						// Start sending file
						// JSONObject sendingFile = new JSONObject();
						RandomAccessFile byteFile = new RandomAccessFile(f, "r");
						byte[] sendingBuffer = new byte[MAXFILESIZE];
						int num;
						// While there are still bytes to send..
						while ((num = byteFile.read(sendingBuffer)) > 0) {
							output.write(Arrays.copyOf(sendingBuffer, num));
						}
						byteFile.close();
					} catch (IOException e) {
						e.printStackTrace();
					}
					JSONObject json_output2 = new JSONObject();
					json_output2.put("resultSize", 1);
					output.writeUTF(json_output2.toString());
					output.flush();
					log.log(Level.INFO, "message sent:" + json_output2.toString());
					client.close();
				} else {
					log.log(Level.SEVERE, "error:" + "file cannot be read!");
				}
			}

		} catch (IOException e) {
			e.printStackTrace();
			log.log(Level.SEVERE, e.toString());
		}
	}

	private static String readssl(SSLSocket sslclient, Logger log) {
		String string = null;
		BufferedReader in;
		try {
			in = new BufferedReader(new InputStreamReader(sslclient.getInputStream()));

			// Read input from the client and print it to the screen
			while ((string = in.readLine()) != null) {

				log.log(Level.INFO, "[received]: " + string);
				return string;
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
		return string;

	}

	private static void sslserveClient(SSLSocket sslclient, Logger log) {
		try {
			sslclient.setKeepAlive(true);
		} catch (SocketException e2) {
			// TODO Auto-generated catch block
			e2.printStackTrace();
		}
		JSONObject json_output = new JSONObject();
		JSONObject json_input = null;
		Boolean IsError = false;
		String string = null;
		// check JSON
		try {
			BufferedReader in = new BufferedReader(new InputStreamReader(sslclient.getInputStream()));
			// Read input from the client and print it to the screen
			while ((string = in.readLine()) != null) {
				log.log(Level.INFO, "[received]: " + string);
				break;
			}
			json_input = new JSONObject(string);

		} catch (JSONException e) {
			log.log(Level.WARNING, e.toString());
			json_output = PutError("missing or incorrect type for command", json_output);
			try {
				sslclient.close();
			} catch (IOException e1) {
				log.log(Level.SEVERE, e1.toString());
				e1.printStackTrace();
			}
			IsError = true;
		} catch (IOException e) {
			log.log(Level.WARNING, e.toString());
			IsError = true;
			try {
				sslclient.close();
			} catch (IOException e1) {
				log.log(Level.SEVERE, e1.toString());
			}
		}

		// check command key
		if (!json_input.has("command")) {
			json_output = PutError("missing for command", json_output);
			IsError = true;
		}

		if (!IsError) {
			String current_cmd = json_input.get("command").toString();
			Boolean DoNotClose = false;
			if (current_cmd.equals("PUBLISH")) {
				json_output = publish(json_input);
				socketsendssl(sslclient, json_output.toString());
			} else if (current_cmd.equals("REMOVE")) {
				json_output = remove(json_input);
				socketsendssl(sslclient, json_output.toString());
			} else if (current_cmd.equals("SHARE")) {
				json_output = share(json_input);
				socketsendssl(sslclient, json_output.toString());
			} else if (current_cmd.equals("QUERY")) {
				queryssl(json_input, sslclient);
				DoNotClose = true;
			} else if (current_cmd.equals("FETCH")) {
				fetchssl(json_input, sslclient);
				DoNotClose = true;
			} else if (current_cmd.equals("SUBSCRIBE")) {
				addsubscribessl(json_input, sslclient);
				DoNotClose = true;
			}

			else if (current_cmd.equals("EXCHANGE"))
				json_output = exchange(json_input, true);
			else {
				json_output.put("response", "error");
				json_output.put("errorMessage", "invalid command");
			}
			if (!DoNotClose) {
				try {
					sslclient.close();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}

		} else {
			log.log(Level.SEVERE, "error in processing ");
		}
	}

	private static void serveClient(Socket client, Logger log) {
		JSONObject json_output = new JSONObject();
		DataInputStream input = null;
		JSONObject json_input = null;
		Boolean IsError = false;
		// check JSON
		try {
			input = new DataInputStream(client.getInputStream());
			json_input = new JSONObject(input.readUTF());
		} catch (JSONException e) {
			log.log(Level.WARNING, e.toString());
			json_output.put("response", "error");
			json_output.put("errorMessage", "missing or incorrect type for command");
			IsError = true;
		} catch (IOException e) {
			log.log(Level.SEVERE, e.toString());
			IsError = true;
			return;
		}

		// check command key
		if (!json_input.has("command")) {
			json_output = PutError("missing for command", json_output);
			log.log(Level.WARNING, "cannot get command");
			IsError = true;
		}

		if (!IsError) {
			DataOutputStream output = null;
			try {
				output = new DataOutputStream(client.getOutputStream());
				log.log(Level.INFO, "[received]:" + json_input);
				String current_cmd = json_input.get("command").toString();
				Boolean DoNotClose = false;
				Boolean DoNotReply = false;
				if (current_cmd.equals("PUBLISH"))
					json_output = publish(json_input);
				else if (current_cmd.equals("REMOVE"))
					json_output = remove(json_input);
				else if (current_cmd.equals("SHARE"))
					json_output = share(json_input);
				else if (current_cmd.equals("QUERY")) {
					query(json_input, client);
					DoNotReply = true;
				} else if (current_cmd.equals("FETCH")) {
					fetch(json_input, client);
					DoNotReply = true;
				} else if (current_cmd.equals("SUBSCRIBE")) {
					addsubscribe(json_input, client);
					DoNotReply = true;
				} else if (current_cmd.equals("EXCHANGE"))
					json_output = exchange(json_input, false);
				else {
					json_output.put("response", "error");
					json_output.put("errorMessage", "invalid command");
				}
				if (!DoNotReply) {

					output.writeUTF(json_output.toString());
					output.flush();
					log.log(Level.INFO, "[sent]:" + json_output.toString());

					if (!DoNotClose) {
						client.close();
					}
				}
			} catch (IOException e) {
				// TODO Auto-generated catch block
				log.log(Level.SEVERE, e.toString());
			}
		} else {

		}
	}

	private static void socketsend(Socket client, String msg) {
		try {
			DataOutputStream output;
			output = new DataOutputStream(client.getOutputStream());
			output.writeUTF(msg);
			log.log(Level.INFO, "[sent:]:" + msg);
			output.flush();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			log.log(Level.WARNING, "[sending failed:]:" + msg);
			e.printStackTrace();
		}
	}

	private static String read(Socket client) {
		String msg = null;
		try {
			DataInputStream input;

			input = new DataInputStream(client.getInputStream());
			msg = input.readUTF();
			log.log(Level.INFO, "[received:]:" + msg);
			return msg;
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return msg;
		}
	}

	private static void socketsendssl(SSLSocket client, String msg) {
		try {
			OutputStream outputstream = client.getOutputStream();
			OutputStreamWriter outputstreamwriter = new OutputStreamWriter(outputstream);
			BufferedWriter bufferedwriter = new BufferedWriter(outputstreamwriter);
			bufferedwriter.write(msg + "\n");
			bufferedwriter.flush();
			client.setKeepAlive(true);
			client.setSoTimeout(TIMEOUT);
			log.log(Level.INFO, "[sent]:" + msg);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			log.log(Level.WARNING, "[sending failed:]:" + msg);
			e.printStackTrace();
		}
	}

	private static resource JSONtoResource(JSONObject input) {

		String name = "";
		String description = "";
		ArrayList<String> tagsList = new ArrayList<String>();
		String URI = "";
		String channel = "";
		String owner = "";
		String EZserver = null;

		resource re_tmp = new resource();

		if (input.has("tags")) {
			JSONArray JSON_tags = new JSONArray();
			JSON_tags = input.getJSONArray("tags");
			for (Object tag : JSON_tags) {
				tagsList.add(tag.toString());
			}
			if (!re_tmp.setTags(tagsList)) {
				return null;
			}
		}
		if (!re_tmp.setName(input.getString("name"))) {
			return null;
		} else {
			name = input.getString("name");
		}
		if (input.has("uri")) {
			URI = input.getString("uri").replace("\\/", "/");
		} else {
			return null;
		}
		if (input.has("ezserver")) {
			if (!re_tmp.setZEserver(input.getString("ezserver"))) {
				return null;
			} else {
				EZserver = input.getString("ezserver");
			}
		}
		if (!re_tmp.setDescription(input.getString("description"))) {
			return null;
		} else {
			description = input.getString("description");
		}
		if (!re_tmp.setOwner(input.getString("owner"))) {
			return null;
		} else {
			owner = input.getString("owner");
		}
		if (!re_tmp.setChannel(input.getString("channel"))) {
			return null;
		} else {
			channel = input.getString("channel");
		}

		return re_tmp;
	}

	private static resource validtemplate(JSONObject input) {
		resource re_tmp = new resource();
		if (!input.has("resourceTemplate")) {
			return null;
		} else {
			JSONObject validTest = input.getJSONObject("resourceTemplate");

			if (validTest.has("tags")) {
				JSONArray JSON_tags = new JSONArray();
				JSON_tags = validTest.getJSONArray("tags");
				ArrayList<String> qtagsList = new ArrayList<String>();
				for (Object tag : JSON_tags) {
					qtagsList.add(tag.toString());
				}
				if (!re_tmp.setTags(qtagsList)) {
					return null;
				}
			}
			if (!re_tmp.setName(validTest.getString("name"))) {
				return null;
			}
			if (validTest.has("uri")) {

			} else {
				return null;
			}
			if (validTest.has("ezserver")) {
				if (!re_tmp.setZEserver(validTest.getString("ezserver"))) {
					return null;
				}
			}
			if (!re_tmp.setDescription(validTest.getString("description"))) {
				return null;
			}
			if (!re_tmp.setOwner(validTest.getString("owner"))) {
			}
			if (!re_tmp.setChannel(validTest.getString("channel"))) {
				return null;
			}
		}
		return re_tmp;
	}

	private static void addsubscribe(JSONObject input, Socket client) {
		JSONObject json_output = new JSONObject();
		String id = null;
		boolean relayflag = false;
		try {
			id = input.getString("id");
			relayflag = input.getBoolean("relay");
		} catch (Exception e) {
			json_output.put("response", "error");
			json_output.put("errorMessage", "invalid or missing id/relay");
			socketsend(client, json_output.toString());
			return;
		}
		id = input.getString("id");

		JSONObject temp = new JSONObject();
		resource tamplate = validtemplate(input);
		if (null == tamplate) {
			try {
				DataOutputStream output = new DataOutputStream(client.getOutputStream());
				invalid(json_output, output);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		} else {
			temp.put("id", id);
			temp.put("client_input", input);
			temp.put("connection", client);
			temp.put("connection_type", "socket");
			temp.put("count", 0);
			SubscribeList.put(id, temp);
			json_output.put("response", "success");
			json_output.put("id", id);
			if (relayflag) {
				for (Object server : ServerList) {
					JSONObject json = (JSONObject) server;
					input.put("relay", false);
					String ip = json.getString("hostname");
					int port = json.getInt("port");
					SocketFactory socketfactory = (SocketFactory) SocketFactory.getDefault();
					try {
						Socket socket = (Socket) socketfactory.createSocket(ip, port);
						socketsend(socket, input.toString());
						socket.setKeepAlive(true);
						Thread t = new Thread(() -> RelayReader(socket, log));
						t.setDaemon(true);
						t.start();

					} catch (UnknownHostException e) {
						// TODO Auto-generated catch block
						log.log(Level.WARNING, e.toString());
						e.printStackTrace();
					} catch (IOException e) {
						// TODO Auto-generated catch block
						log.log(Level.WARNING, e.toString());
						e.printStackTrace();
					}

				}
			}
			socketsend(client, json_output.toString());
		}
		String str = null;

		str = read(client);

		if (str != null) {
			JSONObject in = new JSONObject(str);
			if (in.getString("command").equals("UNSUBSCRIBE")) {
				SubscribeList.remove(in.getString("id"));
				log.log(Level.INFO, "remove subscribe:" + in.getString("id"));
				try {
					client.close();
					return;
				} catch (IOException e) {
					log.log(Level.INFO, e.toString());
					return;
				}
			}
		}
	}

	private static void addsubscribessl(JSONObject input, SSLSocket client) {
		JSONObject json_output = new JSONObject();
		String id = null;
		boolean relayflag = false;
		try {
			id = input.getString("id");
			relayflag = input.getBoolean("relay");
		} catch (Exception e) {
			json_output.put("response", "error");
			json_output.put("errorMessage", "invalid or missing id/relay");
			socketsendssl(client, json_output.toString());
			return;
		}
		JSONObject temp = new JSONObject();

		resource tamplate = validtemplate(input);
		if (null == tamplate) {
			json_output.put("response", "error");
			json_output.put("errorMessage", "invalid resourceTemplate");
			socketsendssl(client, json_output.toString());
			return;
		} else {
			temp.put("id", id);
			temp.put("client_input", input);
			temp.put("connection", client);
			temp.put("connection_type", "sslsocket");
			temp.put("count", 0);
			SubscribeList.put(id, temp);
			json_output.put("response", "success");
			json_output.put("id", id);
		}
		if (relayflag) {
			for (Object server : SSLServerList) {
				input.put("relay", false);
				JSONObject json = (JSONObject) server;
				String ip = json.getString("hostname");
				int port = json.getInt("port");
				SSLSocketFactory sslsocketfactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
				try {
					SSLSocket socket = (SSLSocket) sslsocketfactory.createSocket(ip, port);
					socketsendssl(socket, input.toString());
					socket.setKeepAlive(true);
					Thread t = new Thread(() -> RelayReaderSSL(socket, log));
					t.setDaemon(true);
					t.start();

				} catch (UnknownHostException e) {
					// TODO Auto-generated catch block
					log.log(Level.WARNING, e.toString());
					e.printStackTrace();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					log.log(Level.WARNING, e.toString());
					e.printStackTrace();
				}

			}

		}

		socketsendssl(client, json_output.toString());
		String str = null;

		str = readssl(client, log);

		if (str != null) {
			JSONObject in = new JSONObject(str);

			if (in.getString("command").equals("UNSUBSCRIBE")) {
				SubscribeList.remove(in.getString("id"));
				log.log(Level.INFO, "remove subscribe:" + in.getString("id"));
				try {
					client.close();
					return;
				} catch (IOException e) {
					log.log(Level.INFO, e.toString());
					return;
				}

			}
		}

	}

	private static boolean resourceFit(resource template, resource resource_input) {

		String tname = template.getName();
		String tdescription = template.getDescription();
		ArrayList<String> ttagsList = new ArrayList<String>();
		ttagsList = template.getTags();
		String tURI = template.getURI();
		String tchannel = template.getChannel();
		String towner = template.getOwner();
		String tEZserver = template.getEZserver();

		// Check whether tags present in the template also are present
		// in the candidate
		boolean tagsTest = true;
		if (ttagsList != null) {
			for (int i = 0; i < ttagsList.size(); i++) {
				boolean test = false;
				for (String tagInResourceR : resource_input.getTags()) {
					if (ttagsList.get(i).toLowerCase().equals(tagInResourceR.toLowerCase())) {
						test = true;
						break;
					}
				}
				if (test == false) {
					tagsTest = false;
					break;
				}
			}
		}
		// The candidate name contains the template name as a substring
		// (for non "" template name)
		boolean nameTest;
		if (resource_input.getName().contains(tname) && !tname.equals("")) {
			nameTest = true;
		} else {
			nameTest = false;
		}
		// The candidate description contains the template description
		// as
		// a substring (for non "" template descriptions)
		boolean desTest;
		if ((resource_input.getDescription().contains(tdescription) && !tdescription.equals(""))
				|| resource_input.getDescription().equals(tdescription)) {
			desTest = true;
		} else {
			desTest = false;
		}
		// If the template contains an owner that is not "", then the
		// candidate owner must equal it
		boolean ownerTest;
		if ((towner != "" && resource_input.getOwner().equals(towner)) || towner.equals("")) {
			ownerTest = true;
		} else {
			ownerTest = false;
		}
		// The template channel equals (case sensitive) the resource
		// channel
		boolean channelTest;
		if (resource_input.getChannel().equals(tchannel)) {
			channelTest = true;
		} else {
			channelTest = false;
		}
		// If the template contains a URI then the candidate URI matches
		// (case sensitive)
		boolean uriTest;
		if ((resource_input.getURI().equals(tURI) && !tURI.equals("")) || tURI.equals("")) {
			uriTest = true;
		} else {
			uriTest = false;
		}
		// Check QUERY success
		if (channelTest && ownerTest && tagsTest && uriTest
				&& (nameTest || desTest || (tname.equals("") && tdescription.equals("")))) {

			return true;
		} else {
			return false;
		}

	}

	private static void invalid(JSONObject json_output, DataOutputStream output) {
		json_output.put("response", "error");
		json_output.put("errorMessage", "invalid resourceTemplate");
		try {
			output.writeUTF(json_output.toString());
			output.flush();
			log.log(Level.INFO, "[sent]:" + json_output.toString());
		} catch (IOException e) {
			e.printStackTrace();
			log.log(Level.WARNING, e.toString());
		}
	}

	public static void autoExchange(int cli) {
		while (true) {
			log.log(Level.INFO, "length of serverlist " + ServerList.length());
			if (ServerList.length() > 0) {

				String message = "";
				Random random = new Random();
				int randomIndex = random.nextInt(ServerList.length());
				JSONObject randomServer = ServerList.getJSONObject(randomIndex);
				String ip = randomServer.getString("hostname");
				int port = randomServer.getInt("port");
				try {
					SocketFactory socketfactory = (SocketFactory) SocketFactory.getDefault();
					Socket socket = (Socket) socketfactory.createSocket(ip, port);
					DataInputStream input = new DataInputStream(socket.getInputStream());
					DataOutputStream output = new DataOutputStream(socket.getOutputStream());
					JSONObject json_output = new JSONObject();
					json_output.put("command", "EXCHANGE");
					json_output.put("serverList", ServerList);
					output.writeUTF(json_output.toString());
					output.flush();
					log.log(Level.INFO, "[sent]:" + json_output.toString());
					for (int i = 0; i < 100; i++) {
						if (input.available() > 0) {
							message = input.readUTF();
							log.log(Level.INFO, "[received]:" + message);
							break;
						}
						Thread.sleep(100);
					}
					socket.close();
					if (!message.equals("{\"response\":\"success\"}")) {
						ServerList.remove(randomIndex);
						log.log(Level.INFO, ip + port + " removed from serverlist");
						socket.close();
					}
				} catch (UnknownHostException e) {
					ServerList.remove(randomIndex);
					log.log(Level.INFO, ip + port + " removed from serverlist");
					log.log(Level.WARNING, "UnknownHostException:" + e.toString());
				} catch (IOException e) {
					ServerList.remove(randomIndex);
					log.log(Level.INFO, ip + port + " removed from serverlist");
					log.log(Level.WARNING, "IOException:" + e.toString());
				} catch (InterruptedException e) {
					// TODO Auto-generated catch block
					log.log(Level.WARNING, "InterruptedException:" + e.toString());
				}
			}
			try {
				Thread.sleep(cli * 1000);
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				log.log(Level.SEVERE, "autoExchange sleep failed" + e.toString());
			}
		}
	}

	public static void autoSSLExchange(int cli) {
		while (true) {
			log.log(Level.INFO, "length of sslserverlist " + SSLServerList.length());
			if (ServerList.length() > 0) {

				String message = "";
				Random random = new Random();
				int randomIndex = random.nextInt(ServerList.length());
				JSONObject randomServer = SSLServerList.getJSONObject(randomIndex);
				String ip = randomServer.getString("hostname");
				int port = randomServer.getInt("port");
				try {
					SSLSocketFactory sslsocketfactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
					SSLSocket socket = (SSLSocket) sslsocketfactory.createSocket(ip, port);
					socket.setKeepAlive(true);
					DataInputStream input = new DataInputStream(socket.getInputStream());
					DataOutputStream output = new DataOutputStream(socket.getOutputStream());
					JSONObject json_output = new JSONObject();
					json_output.put("command", "EXCHANGE");
					json_output.put("serverList", ServerList);
					output.writeUTF(json_output.toString());
					output.flush();
					log.log(Level.INFO, "[sslsent]:" + json_output.toString());
					for (int i = 0; i < 100; i++) {
						if (input.available() > 0) {
							message = input.readUTF();
							log.log(Level.INFO, "[sslreceived]:" + message);
							break;
						}
						Thread.sleep(100);
					}
					socket.close();
					if (!message.equals("{\"response\":\"success\"}")) {
						ServerList.remove(randomIndex);
						log.log(Level.INFO, ip + port + " removed from serverlist");
						socket.close();
					}
				} catch (UnknownHostException e) {
					ServerList.remove(randomIndex);
					log.log(Level.INFO, ip + port + " removed from serverlist");
					log.log(Level.WARNING, "UnknownHostException:" + e.toString());
				} catch (IOException e) {
					ServerList.remove(randomIndex);
					log.log(Level.INFO, ip + port + " removed from serverlist");
					log.log(Level.WARNING, "IOException:" + e.toString());
				} catch (InterruptedException e) {
					// TODO Auto-generated catch block
					log.log(Level.WARNING, "InterruptedException:" + e.toString());
				}

			}
			try {
				Thread.sleep(cli * 1000);
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				log.log(Level.SEVERE, "autoExchange sleep failed" + e.toString());
			}
		}
	}
}
