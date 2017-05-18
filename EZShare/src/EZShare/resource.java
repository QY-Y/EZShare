package EZShare;

import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStreamReader;
import java.net.URI;

public class resource {
	private static final Logger log = Logger.getLogger(resource.class.getName());
	private String Name = "";
	private String Description = "";
	private ArrayList<String> Tags = new ArrayList<String>();
	private String URI = "";
	private String Channel = "";
	private String Owner = "";
	private String EZserver;

	public Boolean setName(String name) {
		try {
			String tmp = name.trim();
			tmp = remove(tmp);
			Name = tmp;
			return true;
		} catch (Exception e) {
			return false;
		}
	}

	public String getName() {
		return Name;
	}

	public Boolean setDescription(String description) {
		try {
			String tmp = description.trim();
			tmp = remove(tmp);
			Description = tmp;
			return true;
		} catch (Exception e) {
			return false;
		}
	}

	public String getDescription() {
		return Description;
	}

	private String remove(String in) {
		while (!((in.indexOf('\0') == -1))) {
			int index = in.indexOf('\0');
			in = in.substring(0, index) + in.substring(index + 1);
		}
		return in;
	}

	public Boolean setTags(ArrayList<String> string_tags) {
		try {
			for (String tmp : string_tags) {
				tmp = tmp.trim();
				tmp = remove(tmp);
				Tags.add(tmp);

			}
			return true;
		} catch (Exception e) {
			log.log(Level.WARNING, e.toString());
			return false;
		}
	}

	public ArrayList<String> getTags() {
		return Tags;
	}

	public Boolean setURI(String uri, Boolean Isweb) {
		String tmp = uri.trim();
		tmp = remove(tmp);
		uri = tmp;
		if (uri.equals(""))
			return false;
		if (!Isweb) {
			// localURI
			File file = new File(uri.substring(5, uri.length()));
			if (file.exists()) {
				URI = uri;
				return true;
			} else {
				log.log(Level.WARNING, "file cannot be resloved by server,path:" + uri.substring(5, uri.length()));
				return false;
			}
		} else {
			// webURI
			try {
				URI tmp1 = new URI(uri);
				if (tmp1.isAbsolute()) {
					URI = tmp1.toString();
					return true;
				} else {
					return false;
				}
			} catch (Exception e) {
				return false;
			}
		}
	}

	public String getURI() {
		return URI;
	}

	public Boolean setChannel(String channel) {
		try {
			String tmp = channel.trim();
			tmp = remove(tmp);
			Channel = tmp;
			return true;
		} catch (Exception e) {
			return false;
		}
	}

	public String getChannel() {
		return Channel;
	}

	public Boolean setOwner(String owner) {
		try {
			String tmp = owner.trim();
			tmp = remove(tmp);
			if (tmp.equals("*"))
				return false;
			Owner = tmp;
			return true;
		} catch (Exception e) {
			return false;
		}
	}

	public String getOwner() {
		return Owner;
	}

	public Boolean setZEserver(String ezserver) {
		try {
			String tmp = ezserver.trim();
			tmp = remove(tmp);
			EZserver = tmp;
			return true;
		} catch (Exception e) {
			return false;
		}
	}

	public String getEZserver() {
		return EZserver;
	}

	public String[] getKey() {
		// return primary key String list getowner channel uri
		try {
			String[] tmp = { getOwner(), getChannel(), getURI() };
			return tmp;
		} catch (Exception e) {
			throw e;
		}
	}
}