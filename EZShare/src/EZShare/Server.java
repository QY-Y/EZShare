package EZShare;

import java.io.BufferedReader;
import java.io.DataInputStream;

import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.RandomAccessFile;

import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.net.URL;
import java.net.UnknownHostException;

import CLI.cliserver;
import EZShare.resource;

import java.util.logging.Logger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.json.*;
import java.io.InputStream;

import java.util.logging.Level;

public class Server {
	private static final Logger log = Logger.getLogger(Server.class.getName());
	private static String secret = "abc";
	private static JSONArray ServerList = new JSONArray();
	private static JSONArray SSLServerList = new JSONArray();
	private static ArrayList<String> PublicChannel = new ArrayList<String>();
	private static ArrayList<resource> ResourcesList = new ArrayList<resource>();
	private static JSONObject Channels = new JSONObject();
	private static int cil = 1;
	private static int eil = 600;
	private static int port = 3000;
	private static int sslport = 3781;
	private static JSONObject BlackList = new JSONObject();
	private static int MAXFILESIZE = 20 * 1024 * 1024;
	private static int MAXthread = 100;

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
		 String path = Thread.currentThread().
		 getContextClassLoader().getResource("EZShare/server.jks").getPath();
		 System.setProperty("javax.net.ssl.keyStore", path);

//		System.setProperty("javax.net.ssl.keyStore", "serverKeystore/server.jks");
		System.setProperty("javax.net.ssl.keyStorePassword", "sdfjkl");
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

		try {
			Thread.sleep(1000 * 3600 * 24);
		} catch (InterruptedException e) {
			log.log(Level.SEVERE, e.toString());
			return;
		}
	}

	private static void SSL_LISTEN(SSLServerSocket serversocket) {
		ExecutorService SSLpool = Executors.newFixedThreadPool(MAXthread / 2);
		while (true) {
			try {
				serversocket.setNeedClientAuth(true);
				SSLSocket client = (SSLSocket) serversocket.accept();
				String client_address = client.getInetAddress().toString();
				if (!BlackList.has(client_address)) {
					BlackList.put(client_address, System.currentTimeMillis());
					// Start a new thread for a connection
					// SSLpool.execute(new SSLClientHandler(client, log));
					Thread t = new Thread(() -> sslserveClient(client));
					t.setDaemon(true);
					t.start();
				} else {
					client.close();
					log.log(Level.INFO, client_address + "blocked");
				}
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

		}
	}

	private static void LISTEN(ServerSocket serversocket, Logger log) {
		ExecutorService pool = Executors.newFixedThreadPool(MAXthread / 2);
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
				// TODO Auto-generated catch block
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
				// TODO Auto-generated catch block
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
			if (StringListSame(tmp.getKey(), current_key)) {
				ResourcesList.remove(tmp);
				log.log(Level.WARNING,
						"resource removed:" + tmp.getKey()[0] + "," + tmp.getKey()[1] + "," + tmp.getKey()[2]);
				output.put("response", "success");
				return output;
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
			output.put("response", "success");
			return output;
		} catch (JSONException e) {
			output.put("response", "error");
			output.put("errorMessage", "missing or invalid resource");
			log.log(Level.WARNING, e.toString());
			return output;
		}
	}

	private static void query(JSONObject input, SSLSocket client) {
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

			}
		} catch (IOException e) {
			e.printStackTrace();
			log.log(Level.SEVERE, e.toString());
		}
	}

	private static void fetch(JSONObject input, SSLSocket client) {
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
				} else {
					log.log(Level.SEVERE, "error:" + "file cannot be read!");
				}
			}

		} catch (IOException e) {
			e.printStackTrace();
			log.log(Level.SEVERE, e.toString());
		}

	}

	private static void sslserveClient(SSLSocket client) {
		JSONObject json_output = new JSONObject();
		SSLSocket clientSocket = client;
		InputStream input = null;
		JSONObject json_input = null;
		Boolean IsError = false;
		// check JSON
		try {
			input = client.getInputStream();
			InputStreamReader inputstreamreader = new InputStreamReader(input);
			BufferedReader bufferedreader = new BufferedReader(inputstreamreader);
			input = new DataInputStream(clientSocket.getInputStream());
			json_input = new JSONObject(input.read());

		} catch (JSONException e) {
			log.log(Level.WARNING, e.toString());
			json_output = PutError("missing or incorrect type for command",json_output);
			try {
				client.close();
			} catch (IOException e1) {
				log.log(Level.SEVERE, e1.toString());
				e1.printStackTrace();
			}
			IsError = true;
		} catch (IOException e) {
			log.log(Level.WARNING, e.toString());
			IsError = true;
			try {
				client.close();
			} catch (IOException e1) {
				log.log(Level.SEVERE, e1.toString());
			}
			return;

		}

		// check command key
		if (!json_input.has("command")) {
			json_output = PutError("missing for command",json_output);
			IsError = true;
		}

		if (!IsError) {
			DataOutputStream output = null;
			try {
				output = new DataOutputStream(clientSocket.getOutputStream());
				log.log(Level.INFO, "[received]:" + json_input);
				String current_cmd = json_input.get("command").toString();
				Boolean IsQueryorFetch = false;
				if (current_cmd.equals("PUBLISH"))
					json_output = publish(json_input);
				else if (current_cmd.equals("REMOVE"))
					json_output = remove(json_input);
				else if (current_cmd.equals("SHARE"))
					json_output = share(json_input);
				else if (current_cmd.equals("QUERY")) {
					query(json_input, clientSocket);
					IsQueryorFetch = true;
				} else if (current_cmd.equals("FETCH")) {
					fetch(json_input, clientSocket);
					IsQueryorFetch = true;
				}

				else if (current_cmd.equals("EXCHANGE"))
					json_output = exchange(json_input, true);
				else {
					json_output.put("response", "error");
					json_output.put("errorMessage", "invalid command");
				}
				if (!IsQueryorFetch) {
					log.log(Level.INFO, "[sent]:" + json_output.toString());
					output.writeUTF(json_output.toString());
					output.flush();
					client.close();
				}
			} catch (IOException e) {
				// TODO Auto-generated catch block
				log.log(Level.SEVERE, e.toString());
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
			json_output.put("response", "error");
			json_output.put("errorMessage", "missing for command");
			log.log(Level.WARNING, "cannot get command");
			IsError = true;
		}

		if (!IsError) {
			DataOutputStream output = null;
			try {
				output = new DataOutputStream(client.getOutputStream());
				log.log(Level.INFO, "[received]:" + json_input);
				String current_cmd = json_input.get("command").toString();
				Boolean IsQueryorFetch = false;
				if (current_cmd.equals("PUBLISH"))
					json_output = publish(json_input);
				else if (current_cmd.equals("REMOVE"))
					json_output = remove(json_input);
				else if (current_cmd.equals("SHARE"))
					json_output = share(json_input);
				else if (current_cmd.equals("QUERY")) {
					// query(json_input, clientSocket);
					IsQueryorFetch = true;
				} else if (current_cmd.equals("FETCH")) {
					// fetch(json_input, clientSocket);
					IsQueryorFetch = true;
				}

				else if (current_cmd.equals("EXCHANGE"))
					json_output = exchange(json_input, false);
				else {
					json_output.put("response", "error");
					json_output.put("errorMessage", "invalid command");
				}
				if (!IsQueryorFetch) {
					log.log(Level.INFO, "[sent]:" + json_output.toString());
					output.writeUTF(json_output.toString());
					output.flush();
					client.close();
				}
			} catch (IOException e) {
				// TODO Auto-generated catch block
				log.log(Level.SEVERE, e.toString());
			}
		} else {

		}
	}

	private static void invalid(JSONObject json_output, DataOutputStream output) {
		json_output.put("response", "error");
		json_output.put("errorMessage", "invalid resourceTemplate");
		try {
			output.writeUTF(json_output.toString());
			output.flush();
			log.log(Level.INFO, "message sent:" + json_output.toString());
		} catch (IOException e) {
			e.printStackTrace();
			log.log(Level.SEVERE, e.toString());
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
			log.log(Level.INFO, "length of serverlist " + ServerList.length());
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
