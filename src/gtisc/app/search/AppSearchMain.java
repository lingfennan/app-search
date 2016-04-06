package gtisc.app.search;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.ParseException;
import org.apache.commons.cli.PosixParser;

import gtisc.jobrunner.JobRunner.AppSearchConfig;


public class AppSearchMain {
	public static org.apache.commons.cli.Options options = null;
	private static AppSearchConfig config = null;
	
	private static void buildOptions() {
		options = new org.apache.commons.cli.Options();

		options.addOption("job", true, "the name of the job to run. Currently support: search and dumpConfig!");
		options.addOption("apk", true, "apk file");
		options.addOption("apkDir", true, "path to a folder containing apk files");
		options.addOption("androidJarDir", true, "android jars directory");
		options.addOption("configPath", true, "The path to the configuration file");
		options.addOption("resultDir", true, "The directory to store the results");
		options.addOption("sootOutDir", true, "out dir, needed in soot to produce intermediate results");
		options.addOption("consolePrint", false, "whether or not to print analysis result to terminal");
		options.addOption("binaryConfig", false, "Whether the configurations are in binary or not!");
		options.addOption("binaryOutput", false, "Whether the output should be stored in binary or not!");
		options.addOption("keepSootOutput", false, "Whether to keep the soot output or not (default false)!");
	}

	private static void parseOptions(String[] args) {
		Locale locale = new Locale("en", "US");
		Locale.setDefault(locale);

		CommandLineParser parser = new PosixParser();
		CommandLine commandLine;
		AppSearchConfig.Builder configBuilder = AppSearchConfig.newBuilder();

		try {
			commandLine = parser.parse(options, args);

			commandLine.getArgs();
			org.apache.commons.cli.Option[] clOptions = commandLine.getOptions();

			for (int i = 0; i < clOptions.length; i++) {
				org.apache.commons.cli.Option option = clOptions[i];
				String opt = option.getOpt();

				if (opt.equals("job")) {
					configBuilder.setJobName(commandLine.getOptionValue("job"));
				} else if (opt.equals("apk")) {
					configBuilder.setApkPath(commandLine.getOptionValue("apk"));
				} else if (opt.equals("apkDir")) {
					configBuilder.setApkDir(commandLine.getOptionValue("apkDir"));
				} else if (opt.equals("androidJarDir")) {
					configBuilder.setAndroidJarDirPath(commandLine.getOptionValue("androidJarDir"));
					configBuilder.setForceAndroidJarPath(configBuilder.getAndroidJarDirPath() + "/android-21/android.jar");
				} else if (opt.equals("configPath")) {
					configBuilder.setConfigPath(commandLine.getOptionValue("configPath"));
				} else if (opt.equals("resultDir")) {
					configBuilder.setResultDir(commandLine.getOptionValue("resultDir"));
				} else if (opt.equals("sootOutDir")) {
					configBuilder.setSootOutDir(commandLine.getOptionValue("sootOutDir"));
				} else if (opt.equals("consolePrint")) {
					configBuilder.setConsolePrint(true);
				} else if (opt.equals("binaryConfig")) {
					configBuilder.setBinaryConfig(true);
				} else if (opt.equals("binaryOutput")) {
					configBuilder.setBinaryOutput(true);
				} else if (opt.equals("keepSootOutput")) {
					configBuilder.setKeepSootOutput(true);
				} 
				config = configBuilder.build();
			}
		} catch (ParseException ex) {
			ex.printStackTrace();
			return;
		}
	}

	public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
		// enable assertion
		ClassLoader.getSystemClassLoader().setDefaultAssertionStatus(true);

		buildOptions();
		parseOptions(args);
		AppSearch appSearch = new AppSearch(config);
		switch(config.getJobName()) {
		case "dumpConfig":
			// The demo config
			appSearch.saveConfig(config.getResultDir(), false);
			// The new config
			appSearch.saveConfigBuilder(config.getResultDir(), false, appSearch.createScannerConfig());
			break;
		case "search":
			appSearch.analyzeAll();
			break;
		}
	}
}
