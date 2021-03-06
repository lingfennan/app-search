package gtisc.app.search;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.xmlpull.v1.XmlPullParserException;

import com.google.common.collect.Lists;
import com.google.protobuf.TextFormat;

import gtisc.apiscanner.ApiScanner.Application;
import gtisc.apiscanner.ApiScanner.CallSite;
import gtisc.apiscanner.ApiScanner.ConjunctRule;
import gtisc.apiscanner.ApiScanner.DisjunctRule;
import gtisc.apiscanner.ApiScanner.MatchedRecord;
import gtisc.apiscanner.ApiScanner.RegexRule;
import gtisc.apiscanner.ApiScanner.Result;
import gtisc.apiscanner.ApiScanner.ScannerConfig;
import gtisc.apiscanner.ApiScanner.ScannerRule;
import gtisc.apiscanner.ApiScanner.SimpleRule;
import gtisc.jobrunner.JobRunner.AppAnalysisConfig;
import soot.Body;
import soot.BodyTransformer;
import soot.PackManager;
import soot.ResolutionFailedException;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.Transform;
import soot.Type;
import soot.Unit;
import soot.jimple.InvokeExpr;

public class AppSearch {
	// The matching rules
	private ScannerConfig scannerConfig;
	// The environment variables
	private AppAnalysisConfig jobConfig;

	public AppSearch(AppAnalysisConfig jobConfig) {
		// job config
		this.jobConfig = AppAnalysisConfig.newBuilder().mergeFrom(jobConfig).build();
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
			ProtoBufferUtil.saveMessage(result.build(), resultFile, jobConfig.getBinaryOutput());
		}
	}

	public Application processAPK(File apkPath) throws NoSuchAlgorithmException, IOException {
		System.out.println("Trying to process: " + apkPath.getName());
		
		// maps SootMethod to method bodies
		final ConcurrentHashMap<SootMethod, Body> bodies = new ConcurrentHashMap<SootMethod, Body>();

		// For methods implemented by user, i.e. application classes! 
		// maps package name to the set of contained SootMethods
		Map<String, Set<SootMethod>> packageDefs = new HashMap<String, Set<SootMethod>>();
		// maps class name to SootMethods
		Map<String, Set<SootMethod>> classDefs = new HashMap<String, Set<SootMethod>>();
		// maps method Signature to SootMethod
		Map<String, SootMethod> methodDefs = new HashMap<String, SootMethod>();
		// maps method Name or SubSignature to SootMethods
		Map<String, Set<SootMethod>> methodNameOrSubSigDefs = new HashMap<String, Set<SootMethod>>();
		// TODO: ArgTypes and ReturnType is currently inefficient now! Implement a more efficient version when have time.
		// maps arg types to SootMethods
		Map<String, Set<SootMethod>> argTypesDefs = new HashMap<String, Set<SootMethod>>();
		// maps return type to SootMethods
		Map<String, Set<SootMethod>> returnTypeDefs = new HashMap<String, Set<SootMethod>>();

		// For methods that's not analyzed yet, i.e. non-application classes!
		// maps package name to the set of calling sites
		Map<String, Set<SootMethod>> packageInvocations = new HashMap<String, Set<SootMethod>>();
		// maps class name to the set of calling sites		
		Map<String, Set<SootMethod>> classInvocations = new HashMap<String, Set<SootMethod>>();
		// maps method Signature to method invocation unit and the caller SootMethod
		Map<String, SootMethod> methodInvocations = new HashMap<String, SootMethod>();
		// maps method name or SubSignature to method invocation unit and the caller SootMethod
		Map<String, Set<SootMethod>> methodNameOrSubSigInvocations = new HashMap<String, Set<SootMethod>>();
		
		// TODO: ArgTypes and ReturnType is currently inefficient now! 
		// maps arg types to the invocation SootMethod
		Map<String, Set<SootMethod>> argTypesInvocations = new HashMap<String, Set<SootMethod>>();
		// maps return type to SootMethods
		Map<String, Set<SootMethod>> returnTypeInvocations = new HashMap<String, Set<SootMethod>>();
		// maps calling sites to callers
		Map<SootMethod, Set<SootMethod>> callee2caller = new HashMap<SootMethod, Set<SootMethod>>();
		
		// TODO(Ruian): how to deal with raw strings? should and how can deal with arg types and return types?
		// maps arg types or return types to method invocation unit and the caller SootMethod
		// multiple arg types are concatenated together to form a string, the arg types should be sorted to make it robust
		// Map argsOrReturnInvocation = new HashMap<String, Pair<Unit, SootMethod>>();
		soot.options.Options.v().set_src_prec(soot.options.Options.src_prec_apk);
		soot.options.Options.v().set_output_format(soot.options.Options.output_format_none);
		soot.options.Options.v().set_allow_phantom_refs(true);
		soot.options.Options.v().set_whole_program(true);
		soot.options.Options.v().set_process_multiple_dex(true);
		
		PackManager.v().getPack("jtp").add(new Transform("jtp.appSearch", new BodyTransformer() {
			@Override
			protected void internalTransform(Body b, String phaseName, Map<String, String> options) {
				// collect methods
				bodies.put(b.getMethod(), b);
			}
		}));
		
		String fname = apkPath.getName();
		String sootOutDir = jobConfig.getSootOutDir() + File.separator + fname.split(AppSearchUtil.apkSuffix)[0];
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
		
		
		/* Invocation related, these are information that is actually invoked
		 */
		// Classes
		for (SootClass sootClass : Scene.v().getClasses()) {
			List<SootMethod> methods = sootClass.getMethods();
			for (SootMethod sootMethod : methods) {

				/* Definitions. For methods implemented by user, i.e. application classes! */
				if (sootClass.isApplicationClass()) {
					// collect signature, subsig, method name
					methodDefs.put(sootMethod.getSignature(), sootMethod);  // signature
					String methodSubSig = sootMethod.getSubSignature();  // subsig
					if (!methodNameOrSubSigDefs.containsKey(methodSubSig))
						methodNameOrSubSigDefs.put(methodSubSig, new HashSet<SootMethod>());
					methodNameOrSubSigDefs.get(methodSubSig).add(sootMethod);
					String methodName = sootMethod.getName();  // method name
					if (!methodNameOrSubSigDefs.containsKey(methodName))
						methodNameOrSubSigDefs.put(methodName, new HashSet<SootMethod>());
					methodNameOrSubSigDefs.get(methodName).add(sootMethod);
					
					// collect method arg types and return types
					List<String> args = new ArrayList<String>();
					for (Type t : sootMethod.getParameterTypes()) {
						args.add(t.toString());
					}
					String argType = String.join(",", args);
					String returnType = sootMethod.getReturnType().toString();
					if (!argTypesDefs.containsKey(argType))
						argTypesDefs.put(argType, new HashSet<SootMethod>());
					argTypesDefs.get(argType).add(sootMethod);
					if (!returnTypeDefs.containsKey(returnType)) 
						returnTypeDefs.put(returnType, new HashSet<SootMethod>());
					returnTypeDefs.get(returnType).add(sootMethod);
									
					// collect class
					if (sootClass.isApplicationClass()) {
						if (!classDefs.containsKey(sootClass.getName()))
							classDefs.put(sootClass.getName(), new HashSet<SootMethod>());
						classDefs.get(sootClass.getName()).add(sootMethod);
						if (!packageDefs.containsKey(sootClass.getPackageName()))
							packageDefs.put(sootClass.getPackageName(), new HashSet<SootMethod>());
						packageDefs.get(sootClass.getPackageName()).add(sootMethod);
					}
					
					// collect interfaces
					List<SootClass> interfaceStack = Lists.newArrayList(sootClass.getInterfaces());
					while (!interfaceStack.isEmpty()) {
						SootClass topInterface = interfaceStack.remove(interfaceStack.size() - 1);
						if (topInterface.isApplicationClass()) {
							if (!classDefs.containsKey(topInterface.getName()))
								classDefs.put(topInterface.getName(), new HashSet<SootMethod>());
							classDefs.get(topInterface.getName()).add(sootMethod);
							if (!packageDefs.containsKey(topInterface.getPackageName()))
								packageDefs.put(topInterface.getPackageName(), new HashSet<SootMethod>());
							packageDefs.get(topInterface.getPackageName()).add(sootMethod);
						}
						
						List<SootClass> tmpInterfaces = Lists.newArrayList(topInterface.getInterfaces());
						for (SootClass tmpInterface : tmpInterfaces) {
							if (!classDefs.containsKey(tmpInterface.getName())) {
								interfaceStack.add(tmpInterface);
							}
						}
					}
				}
				
				/* Invocation related, these are information that is actually invoked */
				Body body = null;
				if (bodies.containsKey(sootMethod)) body = bodies.get(sootMethod);
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
						// If the targetMethod is the method that we already marked in internalTransform,
						// we do the same as framework methods, i.e. we don't differentiate defined vs. not-defined methods here
						methodInvocations.put(targetMethod.getSignature(), targetMethod);
						if (!callee2caller.containsKey(targetMethod))
							callee2caller.put(targetMethod, new HashSet<SootMethod>());
						callee2caller.get(targetMethod).add(sootMethod);
						
						// methods
						String subsig = targetMethod.getSubSignature();
						String name = targetMethod.getName();
						if (!methodNameOrSubSigInvocations.containsKey(subsig))
							methodNameOrSubSigInvocations.put(subsig, new HashSet<SootMethod>());
						methodNameOrSubSigInvocations.get(subsig).add(targetMethod);
						if (!methodNameOrSubSigInvocations.containsKey(name))
							methodNameOrSubSigInvocations.put(name, new HashSet<SootMethod>());
						methodNameOrSubSigInvocations.get(name).add(targetMethod);

						// collect method arg types and return types
						List<String> args = new ArrayList<String>();
						for (Type t : targetMethod.getParameterTypes()) {
							args.add(t.toString());
						}
						String argType = String.join(",", args);
						String returnType = targetMethod.getReturnType().toString();
						if (!argTypesInvocations.containsKey(argType))
							argTypesInvocations.put(argType, new HashSet<SootMethod>());
						argTypesInvocations.get(argType).add(targetMethod);
						if (!returnTypeInvocations.containsKey(returnType)) 
							returnTypeInvocations.put(returnType, new HashSet<SootMethod>());
						returnTypeInvocations.get(returnType).add(targetMethod);

						// classes, packages
						SootClass targetClass = targetMethod.getDeclaringClass();
						String targetClassName = targetClass.getName();
						String targetPackageName = targetClass.getPackageName();
						if (!classInvocations.containsKey(targetClassName))
							classInvocations.put(targetClassName, new HashSet<SootMethod>());
						classInvocations.get(targetClassName).add(targetMethod);
						if (!packageInvocations.containsKey(targetPackageName))
							packageInvocations.put(targetPackageName, new HashSet<SootMethod>());
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
			String versionName = "";
			try {
				versionName = processManifest.getVersionName();
				
			} catch (Exception e) {
				// If the version name is not properly parsed, simply set it to null.
				// versionName = Integer.toString(processManifest.getVersionCode());
				e.printStackTrace();
			}
			appBuilder.setVersionName(versionName);
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
		boolean found = mathcesRule(
				// All the definition related
				packageDefs, classDefs, methodDefs, methodNameOrSubSigDefs, argTypesDefs, returnTypeDefs,
				// All the invocation related
				packageInvocations, classInvocations, methodInvocations, methodNameOrSubSigInvocations,
				argTypesInvocations, returnTypeInvocations,
				// The mapping from callee to caller
				callee2caller,
				// The result
				appBuilder);
		
		// Cleanup
		soot.G.reset();
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
			Map<String, Set<SootMethod>> argTypesDefs,
			Map<String, Set<SootMethod>> returnTypeDefs,
			// Non-application classes, such as android.app.*, java.util.*.
			Map<String, Set<SootMethod>> packageInvocations,			
			Map<String, Set<SootMethod>> classInvocations,
			Map<String, SootMethod> methodInvocations,
			Map<String, Set<SootMethod>> methodNameOrSubSigInvocations,
			Map<String, Set<SootMethod>> argTypesInvocations,
			Map<String, Set<SootMethod>> returnTypeInvocations,
			// Maps callee to caller
			Map<SootMethod, Set<SootMethod>> callee2caller,
			// Application.Builder, used to store the search results
			Application.Builder appBuilder
			) {
		boolean someRuleMatched = false;
		for (ScannerRule rule : scannerConfig.getRulesList()) {
			boolean disjunctMatched = false;
			for (DisjunctRule disjunct : rule.getDisjunctRulesList()) {
				boolean conjunctMatched = true;

				// The matched record is for each disjunct rule 
				MatchedRecord.Builder mr = MatchedRecord.newBuilder();
				for (ConjunctRule conjunct : disjunct.getConjunctRulesList()) {
					boolean simpleMatched = true;
					for (SimpleRule simpleRule : conjunct.getSimpleRulesList()) {
						boolean regexRuleMatched = true;
						Set<SootMethod> userMethods = new HashSet<SootMethod>();
						Set<SootMethod> frameworkMethods = new HashSet<SootMethod>();
						boolean initialized = false;

						// Class name
						if (simpleRule.hasClassName()) {
							AppSearchUtil.checkRegexRule(simpleRule.getClassName(), initialized, 
									classDefs, classInvocations, userMethods, frameworkMethods);							
							initialized = true;
						}
						// Method name or SubSignature
						if (simpleRule.hasMethodNameOrSubSignature()) {
							AppSearchUtil.checkRegexRule(simpleRule.getMethodNameOrSubSignature(), initialized,
									methodNameOrSubSigDefs, methodNameOrSubSigInvocations,
									userMethods, frameworkMethods);
							initialized = true;
						}
						// Method Signature
						if (simpleRule.hasMethodSignature()) {
							AppSearchUtil.checkRegexRuleMethod(simpleRule.getMethodSignature(), initialized,
									methodDefs, methodInvocations, userMethods, frameworkMethods);
							initialized = true;
						}
						// Package name
						if (simpleRule.hasPackageName()) {
							AppSearchUtil.checkRegexRule(simpleRule.getPackageName(), initialized,
									packageDefs, packageInvocations, userMethods, frameworkMethods);
							initialized = true;
						}
						// Args Types, note that arg types are combined to form a new rule
						if (simpleRule.getArgTypesCount() > 0) {
							List<String> checkArgTypes = new ArrayList<String>();
							for (RegexRule argType : simpleRule.getArgTypesList()) {
								checkArgTypes.add(argType.getContent());
							}
							RegexRule.Builder checkArgType = RegexRule.newBuilder();
							checkArgType.setContent(String.join(",", checkArgTypes));
							checkArgType.setPartialMatch(simpleRule.getArgTypes(0).getPartialMatch());
							AppSearchUtil.checkRegexRule(checkArgType.build(), initialized,
									argTypesDefs, argTypesInvocations, userMethods, frameworkMethods);
							initialized = true;
						}
						// Return type
						if (simpleRule.hasReturnType()) {
							AppSearchUtil.checkRegexRule(simpleRule.getReturnType(), initialized,
									returnTypeDefs, returnTypeInvocations, userMethods, frameworkMethods);
							initialized = true;
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
						if (regexRuleMatched && !simpleRule.getNegate()) {
							// update appBuilder to log RegexRule information
							System.out.println("Conjunct Rule: " + conjunct.getId() + "\n\tSimple Rule: " + simpleRule.getId());
							System.out.println(userMethods);
							System.out.println(frameworkMethods);

							// combine userMethods and frameworkMethods
							userMethods.addAll(frameworkMethods);
							for (SootMethod matchedMethod : userMethods) {
								CallSite.Builder callSite = CallSite.newBuilder();
								callSite.setCallee(AppSearchUtil.getCallDescription(matchedMethod));
								if (callee2caller.containsKey(matchedMethod)) {
									for (SootMethod caller: callee2caller.get(matchedMethod)) {
										callSite.addCallers(AppSearchUtil.getCallDescription(caller));
									}
								}
								mr.addCallSites(callSite.build());
							}
						}
					}
					conjunctMatched &= simpleMatched;
					
					if (simpleMatched) {
						// update appBuilder to log SimpleRule information
					}
				}
				// Each disjunct rule
				if (conjunctMatched) {
					mr.setRuleName(rule.getName());
					mr.setDisjunctId(disjunct.getId());
					for (ConjunctRule cr : disjunct.getConjunctRulesList()) {
						mr.addConjunctIds(cr.getId());
						for (SimpleRule sr : cr.getSimpleRulesList()) mr.addSimpleIds(sr.getId());
					}
					appBuilder.addMatches(mr.build());
				}
				// Update disjunct matched
				disjunctMatched |= conjunctMatched;
				// Break if disjunct rule is satisfied and we don't perform exhaust search
				// If exhaust is true, then evaluate all the disjunct rules.				
				if (disjunctMatched && !disjunct.getExhaust()) break;
			}
			someRuleMatched |= disjunctMatched; 
		}
		
		return someRuleMatched;
	}

	public void saveConfig(String resultDir, boolean binary) {
		AppSearchUtil.saveConfig(resultDir, binary, scannerConfig);
	}
}
