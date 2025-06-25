
// @dep commons-cli:commons-cli:1.5.0
import org.apache.commons.cli.*;

public class CommonsCliDemo {
    public static void main(String[] args) {
        // Define options
        Options options = new Options();

        Option fileOption = Option.builder("f")
                .longOpt("file")
                .hasArg()
                .argName("filename")
                .desc("Input file name")
                .required()
                .build();

        Option verboseOption = new Option("v", "verbose", false, "Enable verbose output");

        options.addOption(fileOption);
        options.addOption(verboseOption);

        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();

        try {
            CommandLine cmd = parser.parse(options, args);

            String filename = cmd.getOptionValue("file");
            boolean verbose = cmd.hasOption("verbose");

            System.out.println("File: " + filename);
            if (verbose) {
                System.out.println("Verbose mode is ON");
            }

        } catch (ParseException e) {
            System.err.println("Parsing failed: " + e.getMessage());
            formatter.printHelp("SimpleCommonsCliDemo", options);
            System.exit(1);
        }
    }
}
