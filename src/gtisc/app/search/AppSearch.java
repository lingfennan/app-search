package gtisc.app.search;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.commons.io.FileUtils;
import org.xmlpull.v1.XmlPullParserException;

import com.google.common.collect.Lists;
import com.google.protobuf.TextFormat;

import gtisc.apiscanner.ApiScanner.Application;
import gtisc.apiscanner.ApiScanner.ConjunctRule;
import gtisc.apiscanner.ApiScanner.DisjunctRule;
import gtisc.apiscanner.ApiScanner.MatchedRecord;
import gtisc.apiscanner.ApiScanner.Result;
import gtisc.apiscanner.ApiScanner.ScannerConfig;
import gtisc.apiscanner.ApiScanner.ScannerRule;
import gtisc.apiscanner.ApiScanner.SimpleRule;
import gtisc.jobrunner.JobRunner.AppSearchConfig;
import soot.Body;
import soot.BodyTransformer;
import soot.PackManager;
import soot.ResolutionFailedException;
import soot.SootClass;
import soot.SootMethod;
import soot.Transform;
import soot.Unit;
import soot.jimple.InvokeExpr;

public class AppSearch {
	// The matching rules
	private ScannerConfig scannerConfig;
	// The environment variables
	private AppSearchConfig jobConfig;
	private Result.Builder result;

	public AppSearch(AppSearchConfig jobConfig) {
		// job config
		this.jobConfig = AppSearchConfig.newBuilder().mergeFrom(jobConfig).build();
		// result
		result = Result.newBuilder();
		// scanner config
		if (jobConfig.hasConfigPath()) {
			try {
				if (jobConfig.getBinaryConfig()) {
					FileInputStream fileInputStream = new FileInputStream(jobConfig.getConfigPath());			
					scannerConfig = ScannerConfig.parseFrom(fileInputStream);
					fileInputStream.close();				
				} else {
					ScannerConfig.Builder sb = ScannerConfig.newBuilder();
					FileReader fileReader = new FileReader(jobConfig.getConfigPath());
					TextFormat.merge(fileReader, sb);
					scannerConfig = sb.build();
					fileReader.close();		
				}
			} catch (IOException e) {
				e.printStackTrace();
			}
		} else {
			scannerConfig = ScannerConfig.newBuilder().setName(AppSearchUtil.defaultConfigName).build();
		}
	}
	
	/*
	 * Analyze all the applications according to the jobConfig and save the analyzed results.
	 */
	public void analyzeAll() throws IOException, NoSuchAlgorithmException  {
		Result.Builder result = Result.newBuilder();
		Application app;
		result.setConfig(scannerConfig);
		File resultFile = null;
		if (jobConfig.hasApkPath()) {
			File apkFile = new File(jobConfig.getApkPath());
			app = processAPK(apkFile);
			if (app != null) result.addApps(app);
			resultFile = new File(jobConfig.getResultDir(), apkFile.getName() + AppSearchUtil.resultSuffix);
		} else if (jobConfig.hasApkDir()) {
			File folder = new File(jobConfig.getApkDir());
			File[] listOfFiles = folder.listFiles();
			for (File f : listOfFiles) {
				if (f.getName().endsWith(AppSearchUtil.apkSuffix)) {
					app = processAPK(f);
					if (app != null) result.addApps(app);  // only process apk files
				}  
			}
			resultFile = new File(jobConfig.getResultDir(), folder.getName() + AppSearchUtil.resultSuffix);
		}
		if (resultFile != null) {
			AppSearchUtil.saveMessage(result.build(), resultFile, jobConfig.getBinaryOutput());
		}
	}

	public Application processAPK(File apkPath) throws NoSuchAlgorithmException, IOException {
		System.out.println("Trying to process: " + apkPath.getName());

		// maps SootMethod to method bodies
		final ConcurrentHashMap<SootMethod, Body> bodies = new ConcurrentHashMap<SootMethod, Body>();
		final ConcurrentHashMap<String, SootClass> appClasses = new ConcurrentHashMap<String, SootClass>();

		// For methods implemented by user, i.e. application classes! 
		// maps package name to the set of contained SootClasses
		final ConcurrentHashMap<String, Set<SootMethod>> packageDefs = new ConcurrentHashMap<String, Set<SootMethod>>();
		// maps class name to SootClasses, and interfaces
		final ConcurrentHashMap<String, Set<SootMethod>> classDefs = new ConcurrentHashMap<String, Set<SootMethod>>();
		// maps method Signature to SootMethod
		final ConcurrentHashMap<String, SootMethod> methodDefs = new ConcurrentHashMap<String, SootMethod>();
		// maps method Name or SubSignature to SootMethods
		final ConcurrentHashMap<String, Set<SootMethod>> methodNameOrSubSigDefs = new ConcurrentHashMap<String, Set<SootMethod>>(); 

		// For methods that's not analyzed yet, i.e. non-application classes!
		// maps package name to the set of calling sites
		Map<String, Set<SootMethod>> packageInvocations = new HashMap<String, Set<SootMethod>>();
		// maps class name to the set of calling sites		
		Map<String, Set<SootMethod>> classInvocations = new HashMap<String, Set<SootMethod>>();
		// maps method Signature to method invocation unit and the caller SootMethod
		Map<String, SootMethod> methodInvocations = new HashMap<String, SootMethod>();
		// maps method name or SubSignature to method invocation unit and the caller SootMethod
		Map<String, Set<SootMethod>> methodNameOrSubSigInvocations = new HashMap<String, Set<SootMethod>>();
		
		// TODO(Ruian): how to deal with raw strings? should and how can deal with arg types and return types?
		// maps arg types or return types to method invocation unit and the caller SootMethod
		// multiple arg types are concatenated together to form a string, the arg types should be sorted to make it robust
		// Map argsOrReturnInvocation = new HashMap<String, Pair<Unit, SootMethod>>();
		soot.options.Options.v().set_src_prec(soot.options.Options.src_prec_apk);
		soot.options.Options.v().set_output_format(soot.options.Options.output_format_J);
		soot.options.Options.v().set_allow_phantom_refs(true);
		soot.options.Options.v().set_whole_program(true);
		
		PackManager.v().getPack("jtp").add(new Transform("jtp.appSearch", new BodyTransformer() {

			protected void addToSetValue(Map<String, Set<SootMethod>> entries, String key, SootMethod value) {
			    Set<SootMethod> values = entries.get(key);
			    if (values == null) {
			        entries.putIfAbsent(key, Collections.synchronizedSet(new HashSet<SootMethod>()));
			        // At this point, there will definitely be a list for the key.
			        // We don't know or care which thread's new object is in there, so:
			        values = entries.get(key);
			    }
			    values.add(value);
			}
			
			@Override
			protected void internalTransform(Body b, String phaseName,
					Map<String, String> options) {
				
				// collect methods
				SootMethod bMethod = b.getMethod();
				bodies.put(bMethod, b);

				// collect signature, subsig, method name
				methodDefs.put(bMethod.getSignature(), bMethod);  // signature
				String methodSubSig = bMethod.getSubSignature();  // subsig
				addToSetValue(methodNameOrSubSigDefs, methodSubSig, bMethod);
				String methodName = bMethod.getName();  // method name
				addToSetValue(methodNameOrSubSigDefs, methodName, bMethod);
				
				// collect class
				SootClass sootClass = bMethod.getDeclaringClass();
				if (sootClass.isApplicationClass()) {
					if (!appClasses.containsKey(sootClass.getName())) {
						appClasses.put(sootClass.getName(), sootClass);
					}
					addToSetValue(classDefs, sootClass.getName(), bMethod);
					addToSetValue(packageDefs, sootClass.getPackageName(), bMethod);
				}
				
				// collect interfaces
				List<SootClass> interfaceStack = Lists.newArrayList(sootClass.getInterfaces());
				while (!interfaceStack.isEmpty()) {
					SootClass topInterface = interfaceStack.remove(interfaceStack.size() - 1);
					if (topInterface.isApplicationClass()) {
						if(!appClasses.containsKey(topInterface.getName())) { 
							appClasses.put(topInterface.getName(), topInterface);
						}
						addToSetValue(classDefs, topInterface.getName(), bMethod);
						addToSetValue(packageDefs, topInterface.getPackageName(), bMethod);
					}
					
					List<SootClass> tmpInterfaces = Lists.newArrayList(topInterface.getInterfaces());
					for (SootClass tmpInterface : tmpInterfaces) {
						if (!appClasses.containsValue(tmpInterface)) {
							interfaceStack.add(tmpInterface);
						}
					}
				}
			}
		}));
		
		String fname = apkPath.getName();
		String sootOutDir = jobConfig.getSootOutDir() + "/" + fname.split(AppSearchUtil.apkSuffix)[0];
		String[] sootArgs = new String[]{
			"-android-jars",
			jobConfig.getAndroidJarDirPath(),
			"-process-dir",
			apkPath.getAbsolutePath(),
			"-d",
			sootOutDir,
			"-force-android-jar",
			jobConfig.getForceAndroidJarPath()
		};
		soot.Main.main(sootArgs);
		
		// Classes
		for (SootClass sootClass : appClasses.values()) {
			List<SootMethod> methods = sootClass.getMethods();
			for (SootMethod method : methods) {		
				Body body = bodies.get(method);
				if (body == null) {
					continue;
				}
				for (Unit unit : body.getUnits()) {
					InvokeExpr invokeExpr = AppSearchUtil.getInvokeExpr(unit);
				
					if (invokeExpr != null) {
						SootMethod targetMethod = null;
						try {
							targetMethod = invokeExpr.getMethod();
						}
						catch (ResolutionFailedException e) {
							e.printStackTrace();
							continue;
						}
						if (bodies.containsKey(targetMethod)) {
							// Already analyzed.
							continue;
						}
						methodInvocations.put(targetMethod.getSignature(), targetMethod);
						
						String subsig = targetMethod.getSubSignature();
						String name = targetMethod.getName();
						methodNameOrSubSigInvocations.putIfAbsent(subsig, new HashSet<SootMethod>());
						methodNameOrSubSigInvocations.get(subsig).add(targetMethod);
						methodNameOrSubSigInvocations.putIfAbsent(name, new HashSet<SootMethod>());
						methodNameOrSubSigInvocations.get(name).add(targetMethod);

						SootClass targetClass = targetMethod.getDeclaringClass();
						String targetClassName = targetClass.getName();
						String targetPackageName = targetClass.getPackageName();
						classInvocations.putIfAbsent(targetClassName, new HashSet<SootMethod>());
						classInvocations.get(targetClassName).add(targetMethod);
						packageInvocations.putIfAbsent(targetPackageName, new HashSet<SootMethod>());
						packageInvocations.get(targetPackageName).add(targetMethod);
					}
					// TODO (ruian): extract all primitive strings in expressions (assignments) 
					// and search for raw strings in them.
				}
			}
		}
		
		// add misc information, parse AndroidManifest.xml, set Activity, Service, Receiver, Provider, Permissions
		System.out.println("Parsing the AndroidManifest.xml to get more information");
		Application.Builder appBuilder = Application.newBuilder();
		appBuilder.setDigest(AppSearchUtil.getDigest(apkPath, "SHA-256"));
		appBuilder.setFilepath(apkPath.getAbsolutePath());
		ProcessManifest processManifest = null;
		try {
			processManifest = new ProcessManifest(apkPath);
			appBuilder.setPackageName(processManifest.getPackageName());
			appBuilder.setVersionName(processManifest.getVersionName());
			appBuilder.addAllActivities(processManifest.getActivityNames());
			appBuilder.addAllServices(processManifest.getServiceNames());
			appBuilder.addAllReceivers(processManifest.getReceiverNames());
			appBuilder.addAllProviders(processManifest.getProviderNames());
			appBuilder.addAllPermissions(processManifest.getPermissions());
		} catch (IOException e) {
			e.printStackTrace();
		} catch (XmlPullParserException e) {
			e.printStackTrace();
		}		

		// Match the rules
		System.out.println("Matching the specified rules");
		boolean found = mathcesRule(packageDefs, classDefs, methodDefs, methodNameOrSubSigDefs,
				packageInvocations, classInvocations, methodInvocations, methodNameOrSubSigInvocations,
				appBuilder);
		
		// Cleanup
		soot.G.reset();
		if (!jobConfig.getKeepSootOutput()) FileUtils.deleteDirectory(new File(sootOutDir));
		if (!found) return null;
		
		System.out.println("Found match for app: " + apkPath.getName());
		return appBuilder.build();
	}
	
	private boolean mathcesRule(
			// Application classes
			Map<String, Set<SootMethod>> packageDefs,
			Map<String, Set<SootMethod>> classDefs,
			Map<String, SootMethod> methodDefs,
			Map<String, Set<SootMethod>> methodNameOrSubSigDefs,
			// Non-application classes, such as android.app.*, java.util.*.
			Map<String, Set<SootMethod>> classInvocations,
			Map<String, Set<SootMethod>> packageInvocations,
			Map<String, SootMethod> methodInvocations,
			Map<String, Set<SootMethod>> methodNameOrSubSigInvocations,
			// Application.Builder, used to store the search results
			Application.Builder appBuilder
			) {
		boolean someRuleMatched = false;
		for (ScannerRule rule : scannerConfig.getRulesList()) {
			boolean disjunctMatched = false;
			for (DisjunctRule disjunct : rule.getDisjunctRulesList()) {
				boolean conjunctMatched = true;
				for (ConjunctRule conjunct : disjunct.getConjunctRulesList()) {
					boolean simpleMatched = true;
					for (SimpleRule simpleRule : conjunct.getSimpleRulesList()) {
						boolean regexRuleMatched = true;
						Set<SootMethod> userMethods = new HashSet<SootMethod>();
						Set<SootMethod> frameworkMethods = new HashSet<SootMethod>();
						boolean initialized = false;
						
						// Method name or SubSignature
						if (simpleRule.hasMethodNameOrSubSignature()) {
							AppSearchUtil.checkRegexRule(simpleRule.getMethodNameOrSubSignature(), initialized,
									methodNameOrSubSigDefs, methodNameOrSubSigInvocations,
									userMethods, frameworkMethods);
							initialized = true;
						}
						// Class name
						if (simpleRule.hasClassName()) {
							AppSearchUtil.checkRegexRule(simpleRule.getClassName(), initialized, 
									classDefs, classInvocations, userMethods, frameworkMethods);
							initialized = true;
						}
						// Package name
						if (simpleRule.hasPackageName()) {
							AppSearchUtil.checkRegexRule(simpleRule.getPackageName(), initialized,
									packageDefs, packageInvocations, userMethods, frameworkMethods);
							initialized = true;
						}
						// Method Signature
						if (simpleRule.hasMethodSignature()) {
							AppSearchUtil.checkRegexRuleMethod(simpleRule.getMethodSignature(), initialized,
									methodDefs, methodInvocations, userMethods, frameworkMethods);
							initialized = true;
						}
						if (simpleRule.getArgTypesCount() > 0) {
							// Not implemented
							System.out.println("not implemented");
						}
						if (simpleRule.hasReturnType()) {
							// Not implemented
							System.out.println("not implemented");
						}
						if (simpleRule.getRawStringsCount() > 0) {
							// Not implemented
							System.out.println("not implemented");
						}
						// Permission string
						boolean allPermissionsFound = true;
						if (simpleRule.getPermissionsCount() > 0) {
							allPermissionsFound = AppSearchUtil.checkRegexRuleList(simpleRule.getPermissionsList(),
									appBuilder.getPermissionsList());
						}
						
						// set regexRuleMatched
						if (initialized) {
							if (userMethods.size() > 0 || frameworkMethods.size() > 0) regexRuleMatched &= true;
							else regexRuleMatched &= false;
								
						}
						if (allPermissionsFound) regexRuleMatched &= true;
						else regexRuleMatched &= false;
						if (simpleRule.getNegate()) regexRuleMatched = !regexRuleMatched;
						simpleMatched &= regexRuleMatched;
						
						if (regexRuleMatched) {
							// update appBuilder to log RegexRule information
							System.out.println(userMethods);
							System.out.println(frameworkMethods);
						}
					}
					conjunctMatched &= simpleMatched;
					
					if (simpleMatched) {
						// update appBuilder to log SimpleRule information
					}
				}
				disjunctMatched |= conjunctMatched;
				if (disjunctMatched) {
					MatchedRecord.Builder mr = MatchedRecord.newBuilder();
					mr.setRuleName(rule.getName());
					mr.setDisjunctId(disjunct.getId());
					for (ConjunctRule cr : disjunct.getConjunctRulesList()) {
						mr.addConjunctIds(cr.getId());
						for (SimpleRule sr : cr.getSimpleRulesList()) mr.addSimpleIds(sr.getId());
					}
					appBuilder.addMatches(mr.build());
					
					// Break if disjunct rule is satisfied and we don't perform exhaust search
					// If exhaust is true, then evaluate all the disjunct rules
					if (!disjunct.getExhaust()) break;
				}
			}
			someRuleMatched |= disjunctMatched; 
		}
		
		return someRuleMatched;
	}

	public void saveConfig(String resultDir, boolean binary) {
		AppSearchUtil.saveConfig(resultDir, binary, scannerConfig);
	}
}