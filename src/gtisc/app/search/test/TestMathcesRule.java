package gtisc.app.search.test;

import static org.junit.Assert.assertEquals;

import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;

import gtisc.apiscanner.ApiScanner.Application;
import gtisc.apiscanner.ApiScanner.MatchedRecord;
import gtisc.app.search.AppSearch;
import gtisc.jobrunner.JobRunner.AppAnalysisConfig;

public class TestMathcesRule {
	AppAnalysisConfig.Builder configBuilder;
	AppSearch appSearch;
	String dataDir = System.getProperty("user.dir") + File.separator + "data";
	String platformDir = "/Users/ruian/Library/Android/sdk/platforms";

	@Before
	public void setUp() {
		configBuilder = AppAnalysisConfig.newBuilder();
		configBuilder.setJobName("search");
		configBuilder.setSootOutDir(dataDir);
		configBuilder.setResultDir(dataDir);
		configBuilder.setAndroidJarDirPath(platformDir);
		configBuilder.setForceAndroidJarPath(platformDir + "/android-21/android.jar");
	}
	
	@Test
	public void TestMatchesRuleClassAndMethodAndCallSites() {
		configBuilder.setApkPath(System.getProperty("user.dir") + File.separator + "test-apps/AndroidServerSocket/app/ServerSocket.apk");
		configBuilder.setConfigPath(dataDir + File.separator + "test-impl-using-serversocket-demo.config");
		appSearch = new AppSearch(configBuilder.build());
		try {
			Application app = appSearch.processAPK(new File(configBuilder.getApkPath()));
			assertEquals(1, app.getMatchesCount());
			assertEquals("socket communication", app.getMatches(0).getRuleName());
			assertEquals("tcp port serversocket", app.getMatches(0).getDisjunctId());
			// Two call sites
			assertEquals(2, app.getMatches(0).getCallSitesCount());
			// both call sites have one callee, three callers
			// call site: ServerSocket-><init>, ServerSocket->accept
			assertEquals(3, app.getMatches(0).getCallSites(0).getCallersCount());
			assertEquals(3, app.getMatches(0).getCallSites(1).getCallersCount());
		} catch (NoSuchAlgorithmException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	@Test
	public void TestMatchesRulesPermissionsAndMethod() {
		configBuilder.setApkPath(dataDir + File.separator + "com.fitbit.FitbitMobile-2142870.apk");
		configBuilder.setConfigPath(dataDir + File.separator + "test-impl-using-fitbit.config");
		appSearch = new AppSearch(configBuilder.build());
		try {
			Application app = appSearch.processAPK(new File(configBuilder.getApkPath()));
			assertEquals(5, app.getMatchesCount());
			Set<String> expectedRules = new HashSet<String>(Arrays.asList(
					new String[]{"facebook-login-method-name", "facebook-login-method-sig", "bluetooth permission",
							"test-partial match", "fitbit package name"}));
			Set<String> matchedRules = new HashSet<String>();
			for (MatchedRecord r: app.getMatchesList()) {
				matchedRules.add(r.getRuleName());
			}
			assertEquals(expectedRules, matchedRules);
		} catch (NoSuchAlgorithmException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
