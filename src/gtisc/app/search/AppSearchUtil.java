package gtisc.app.search;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.xml.bind.DatatypeConverter;

import gtisc.apiscanner.ApiScanner.CallDescription;
import gtisc.apiscanner.ApiScanner.RegexRule;
import gtisc.apiscanner.ApiScanner.ScannerConfig;
import soot.SootClass;
import soot.SootMethod;
import soot.Type;
import soot.Unit;
import soot.Value;
import soot.jimple.AssignStmt;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;

public class AppSearchUtil {
	// Constant values
	public static String apkSuffix = ".apk";
	public static String defaultConfigName = "default";
	public static String configSuffix = ".config";
	public static String resultSuffix = ".search";
	
	
	// Static functions
	public static InvokeExpr getInvokeExpr(Unit unit) {
		InvokeExpr invokeExpr = null;
		if (unit instanceof AssignStmt) {
			AssignStmt assignStmt = (AssignStmt) unit;
			Value rValue = assignStmt.getRightOp();
			if (rValue instanceof InvokeExpr) {
				invokeExpr = (InvokeExpr) rValue;
			}
		} else if (unit instanceof InvokeStmt) {
			InvokeStmt invokeStmt = (InvokeStmt) unit;
			invokeExpr = invokeStmt.getInvokeExpr();
		}
		return invokeExpr;
	}
	
	public static boolean checkRegexRuleList(List<RegexRule> rules, List<String> candidateList) {
		Set<String> candidate = new HashSet<String>(candidateList);
		for (RegexRule rule : rules) {
			Set<String> matched = new HashSet<String>();
			checkRegexRule(rule, candidate, matched);
			if (matched.size() == 0) return false; 
		}
		return true;
	}
	
	public static void checkRegexRule(RegexRule rule, Set<String> candidate, Set<String> matched) {
		String content = rule.getContent();
		if (rule.getPartialMatch()) {
			for (String key: candidate) {
				if (key.contains(content)) {
					matched.add(key);
				}
			}
		} else {
			if (candidate.contains(content)) {
				matched.add(content);
			}
		}
	}
	
	public static void checkRegexRule(RegexRule rule, boolean initialized,
			Map<String, Set<SootMethod>> userChecklist,
			Map<String, Set<SootMethod>> frameworkChecklist,
			Set<SootMethod> userMethods,
			Set<SootMethod> frameworkMethods
			) {
		String content = rule.getContent();
		Set<SootMethod> tmpUserMethods = new HashSet<SootMethod>();
		Set<SootMethod> tmpFrameworkMethods = new HashSet<SootMethod>();
		if (rule.getPartialMatch()) {
			for (String key : userChecklist.keySet()) {
				if (key.contains(content)) {
					tmpUserMethods.addAll(userChecklist.get(key));
				}				
			}
			for (String key : frameworkChecklist.keySet()) {
				if (key.contains(content)) {
					tmpFrameworkMethods.addAll(frameworkChecklist.get(key));										
				}
			}
		} else {
			if (userChecklist.containsKey(content)) {
				tmpUserMethods.addAll(userChecklist.get(content));
			}
			if (frameworkChecklist.containsKey(content)) {
				tmpFrameworkMethods.addAll(frameworkChecklist.get(content));
			}
		}
		// Update userMethods and frameworkMethods
		if (initialized) {
			userMethods.retainAll(tmpUserMethods);
			frameworkMethods.retainAll(tmpFrameworkMethods);
		} else {
			userMethods.addAll(tmpUserMethods);
			frameworkMethods.addAll(tmpFrameworkMethods);
		}
		System.out.println(userMethods);
		System.out.println(frameworkMethods);
	}
	
	public static void checkRegexRuleMethod(RegexRule rule, boolean initialized,
			Map<String, SootMethod> userChecklist,
			Map<String, SootMethod> frameworkChecklist,
			Set<SootMethod> userMethods,
			Set<SootMethod> frameworkMethods) {
		String content = rule.getContent();
		Set<SootMethod> tmpUserMethods = new HashSet<SootMethod>();
		Set<SootMethod> tmpFrameworkMethods = new HashSet<SootMethod>();		
		if (rule.getPartialMatch()) {
			for (String key : userChecklist.keySet()) {
				if (key.contains(content))
					tmpUserMethods.add(userChecklist.get(key));
			}
			for (String key : frameworkChecklist.keySet()) {
				if (key.contains(content))
					tmpFrameworkMethods.add(frameworkChecklist.get(key));
			}
		} else {
			if (userChecklist.containsKey(content)) {
				tmpUserMethods.add(userChecklist.get(content));
			}
			if (frameworkChecklist.containsKey(content)) {
				tmpFrameworkMethods.add(frameworkChecklist.get(content));
			}
		}

		if (initialized) {
			userMethods.retainAll(tmpUserMethods);
			frameworkMethods.retainAll(tmpFrameworkMethods);
		} else {
			userMethods.addAll(tmpUserMethods);
			frameworkMethods.addAll(tmpFrameworkMethods);
		}
	}
	
	public static CallDescription getCallDescription(SootMethod theMethod) {
		CallDescription.Builder callDetail = CallDescription.newBuilder();

		SootClass theClass = theMethod.getDeclaringClass();		
		callDetail.setMethodName(theMethod.getName());
		callDetail.setClassName(theClass.getName());
		callDetail.setPackageName(theClass.getPackageName());
		for (Type argType : theMethod.getParameterTypes()) {
			callDetail.addArgTypes(argType.getEscapedName());
		}
		callDetail.setReturnType(theMethod.getReturnType().getEscapedName());
		callDetail.setMethodSignature(theMethod.getSignature());
		callDetail.setIsApplicationClass(theClass.isApplicationClass());
		callDetail.setIsJavaLibrary(theClass.isJavaLibraryClass());
		callDetail.setIsStatic(theClass.isStatic());
		return callDetail.build();
	}
	
	public static String getDigest(File fin, String alg) throws IOException, NoSuchAlgorithmException {
		// Returns the digest of file fin in lower case
		MessageDigest module = MessageDigest.getInstance(alg);
		return DatatypeConverter.printHexBinary( module.digest(Files.readAllBytes(fin.toPath())) ).toLowerCase();
	}

	public static void saveConfig(String resultDir, boolean binary, ScannerConfig sc) {
		File path;
		if (sc.hasConfigFilename())
			path = new File(sc.getConfigFilename());
		else
			path = new File(resultDir, sc.getName() + configSuffix);
		
		System.out.println("saving config to " + path.getAbsolutePath());
		try {
			ProtoBufferUtil.saveMessage(sc, path, binary);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	public static void saveConfigBuilder(String resultDir, boolean binary, ScannerConfig.Builder sb) {
		File path = new File(resultDir, sb.getName() + configSuffix);
		sb.setConfigFilename(path.getAbsolutePath());
		saveConfig(resultDir, binary, sb.build());
	}
}
