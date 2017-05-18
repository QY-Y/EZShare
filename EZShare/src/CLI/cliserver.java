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

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.UUID;

import org.json.*;

public class cliserver {

	private String[] args = null;
	private Options options = new Options();

	public cliserver(String[] args) {

		this.args = args;

		
		
		
		options.addOption("h", "help", false, "show help");
		final Option Port = Option.builder("p").longOpt("port").desc("Config file for Genome Store").hasArg().build();
		options.addOption(Port);

		final Option Host = Option.builder("ah").longOpt("advertisedhostname").desc("advertised hostname").hasArg()
				.build();
		options.addOption(Host);
		final Option Ci = Option.builder("ci").longOpt("connectionintervallimit")
				.desc("connection interval limit in seconds").hasArg().build();
		options.addOption(Ci);
		final Option Ei = Option.builder("ei").longOpt("exchangeinterval").desc("exchange interval in seconds").hasArg()
				.build();
		options.addOption(Ei);

		final Option S = Option.builder("s").longOpt("secret").desc("secret").hasArg().build();
		options.addOption(S);

		options.addOption("d", "debug", false, "print debug information");
	}

	public JSONObject parse(Logger log) {
		CommandLineParser parser = new DefaultParser();
		JSONObject output = new JSONObject();
		CommandLine cmd = null;
		try {
			cmd = parser.parse(options, args);
			// set default values
			output.put("exchangeinterval", "600");
			InetAddress addr = null;
			addr = InetAddress.getLocalHost();
			output.put("advertisedhostname", addr.getHostName());
			output.put("port", "3000");
			output.put("secret", UUID.randomUUID().toString());
			output.put("debug", "false");
			output.put("connectionintervallimit", "1");

			Option[] args = cmd.getOptions();
			for (Option tmp : args) {
				output.put(tmp.getLongOpt(), tmp.getValue("true"));
			}

			if (cmd.hasOption("h"))
				help();
//			log.log(Level.INFO, "input args:" + output.toString());
			return output;

		} catch (

				ParseException | UnknownHostException e) {
			log.log(Level.SEVERE, "Failed to parse comand line properties", e.toString());
			help();
			System.exit(0);
			return output;
		}
	}

	private void help() {
		// This prints out some help
		HelpFormatter formater = new HelpFormatter();

		formater.printHelp("Main", options);
		System.exit(0);
	}
}
