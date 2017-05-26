package CLI;

import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;

import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import org.json.*;

public class cliclient {

	private String[] args = null;
	private Options options = new Options();

	public cliclient(String[] args) {

		this.args = args;

		options.addOption("h", "help", false, "show help.");

		final Option channel = Option.builder("c").longOpt("channel").desc("channel").hasArg().build();

		options.addOption(channel);

		final Option description = Option.builder("d").longOpt("description").desc("resource description").hasArg()
				.build();
		options.addOption(description);
		options.addOption("sec", "secure", false, "use secure connection");

		options.addOption("de", "debug", false, "print debug information");

		options.addOption("e", "exchange", false, "exchange flag");

		final Option ezserver = Option.builder("ez").longOpt("ezserver").desc("ezserver").hasArg().build();
		options.addOption(ezserver);

		options.addOption("f", "fetch", false, "fetch flag");

		final Option host = Option.builder("ho").longOpt("host").desc("server host, a domain name or IP address")
				.hasArg().build();
		options.addOption(host);

		final Option name = Option.builder("n").longOpt("name").desc("resource name").hasArg().build();
		options.addOption(name);

		final Option owner = Option.builder("o").longOpt("owner").desc("owner name").hasArg().build();
		options.addOption(owner);

		final Option port = Option.builder("p").longOpt("port").desc("server port").hasArg().build();
		options.addOption(port);

		options.addOption("pu", "publish", false, "publish flag");

		options.addOption("q", "query", false, "query flag");

		options.addOption("r", "remove", false, "remove flag");

		final Option relay = Option.builder("re").longOpt("relay").desc("relay ").hasArg().build();
		options.addOption(relay);

		final Option secret = Option.builder("s").longOpt("secret").desc("secret").hasArg().build();
		options.addOption(secret);

		final Option servers = Option.builder("se").longOpt("servers").desc("server list, host1:port1,host2:port2,...")
				.hasArg().build();
		options.addOption(servers);

		options.addOption("sh", "share", false, "share flag");

		final Option tags = Option.builder("t").longOpt("tags").desc("resource tags, tag1,tag2,tag3,...").hasArg()
				.build();
		options.addOption(tags);
		final Option sp = Option.builder("sp").longOpt("sport").desc("secure port").hasArg().build();
		options.addOption(sp);

		final Option uri = Option.builder("u").longOpt("uri").desc("URI").hasArg().build();
		options.addOption(uri);

	}

	public JSONObject parse(Logger log) {
		CommandLineParser parser = new DefaultParser();
		JSONObject output = new JSONObject();
		CommandLine cmd = null;
		try {
			cmd = parser.parse(options, args);

			// Set default values
			output.put("host", "localhost");
			output.put("port", "3000");

			output.put("secret", "");
			output.put("channel", "");
			output.put("owner", "");
			output.put("secure", false);
			//
			if (cmd.hasOption("debug")) {
				output.put("debug", true);
				log.setLevel(Level.ALL);
			} else {
				output.put("debug", false);
				log.setLevel(Level.WARNING);
			}
			if (cmd.hasOption("secure")) {
				output.put("secure", true);
				output.put("port", "3781");
			}

			Option[] args = cmd.getOptions();
			for (Option tmp : args) {
				output.put(tmp.getLongOpt(), tmp.getValue("true"));
			}

			if (cmd.hasOption("h"))
				help();
			log.log(Level.INFO, "input args:" + output.toString());
			return output;

		} catch (ParseException e) {
			log.log(Level.SEVERE, "Failed to parse comand line properties", e);
			help();
			System.exit(0);

		}
		return output;

	}

	private void help() {
		// This prints out some help
		HelpFormatter formater = new HelpFormatter();

		formater.printHelp("Main", options);
		System.exit(0);
	}
}
