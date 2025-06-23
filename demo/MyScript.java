
// @dep org.apache.commons:commons-math3:3.6.1
// @url https://repo1.maven.org/maven2/org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar
// @jar demo/lib/library.jar
// @dir demo/libs
// @dep com.google.guava:guava:33.4.8-jre md5:72920caab34426c5815e3b00f80e3b01

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.math3.util.FastMath;
import org.json.JSONObject;
import com.google.common.collect.Lists;
import java.util.List;

public class MyScript {
    public static void main(String[] args) {
		// Use commons-math via downloaded @dep
        System.out.println("Sin(π/2) = " + FastMath.sin(FastMath.PI / 2));
	    // Use commons-lang via downloaded @url
        System.out.println(StringUtils.capitalize("hello world"));
		// Using library.jar from local @jar
        com.example.lib.LibraryClass.greet();                               
		// Using org.json from local @dir
		JSONObject json = new JSONObject();
        json.put("name", "JavaDepAgent");
        System.out.println("JSON from libs: " + json.toString(2));
		// Use Guava from @dep with md5 validation
		List newList = Lists.newArrayList("a", "b", "c");
        System.out.println("Reversed list: " + Lists.reverse(newList));
	}
}
