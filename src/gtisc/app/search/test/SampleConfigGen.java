package gtisc.app.search.test;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.google.protobuf.Descriptors.FieldDescriptor;

import gtisc.apiscanner.ApiScanner.ConjunctRule;
import gtisc.apiscanner.ApiScanner.DisjunctRule;
import gtisc.apiscanner.ApiScanner.RegexRule;
import gtisc.apiscanner.ApiScanner.ScannerConfig;
import gtisc.apiscanner.ApiScanner.ScannerRule;
import gtisc.apiscanner.ApiScanner.SimpleRule;

public class SampleConfigGen {
	public static RegexRule createRegexRule(String content) {
		RegexRule.Builder rb = RegexRule.newBuilder();
		rb.setContent(content);
		return rb.build();
	}
	
	public static SimpleRule createSimpleRule(HashMap<String, Set<String>> simpleRule, String id) {		
		SimpleRule.Builder sb = SimpleRule.newBuilder();
		sb.setId(id);
		for (FieldDescriptor field : SimpleRule.getDescriptor().getFields()) {
			String key = field.getName();
			if (simpleRule.containsKey(key)) {
				if (field.isRepeated()) {
					for (String content : simpleRule.get(key)) {
						sb.addRepeatedField(field, createRegexRule(content));
					}
				} else {
					if (simpleRule.get(key).size() == 1) {
						sb.setField(field, createRegexRule(simpleRule.get(key).iterator().next()));
					} else {
						System.out.println("Incorrect format of simpleRule: " + simpleRule);
					}
				}
			}
		}
		sb.setNegate(true);
		return sb.build();
	}
	
	public static ConjunctRule createConjunctRule(List< HashMap<String, Set<String>> > conjunctRule, String id) {
		// HashMap<String, Set<String>>
		ConjunctRule.Builder cr = ConjunctRule.newBuilder();
		cr.setId(id);
		
		for (HashMap<String, Set<String>> simpleRule : conjunctRule) {
			cr.addSimpleRules(createSimpleRule(simpleRule, id));
		}
		return cr.build();
	}
	
	public static DisjunctRule createDisjunctRule(List<List< HashMap<String, Set<String>> > > disjunctRule, String id) {
		// List< List< HashMap<String, Set<String>> > >
		DisjunctRule.Builder dr = DisjunctRule.newBuilder();
		dr.setId(id);
		
		for (List< HashMap<String, Set<String>> > conjunctRule : disjunctRule) {
			dr.addConjunctRules(createConjunctRule(conjunctRule, id));
		}
		return dr.build();
	}
	
	public static ScannerRule createScannerRule(List<List<List< HashMap<String, Set<String>> > > > scannerRule, String name) {
		ScannerRule.Builder sr = ScannerRule.newBuilder();
		sr.setName(name);
		int i = 0;
		for (List<List< HashMap<String, Set<String>> > > disjunctRule : scannerRule) {
			sr.addDisjunctRules(createDisjunctRule(disjunctRule, Integer.toString(i++)));
		}
		return sr.build();
	}
	
	public static ScannerConfig.Builder createScannerConfig() {
		// This function is used to create configurations by hand in code, this is used to generate samples of configurations
		// to guide manual edit of configs.
		ScannerConfig.Builder scb = ScannerConfig.newBuilder();
		scb.setName("port-backdoor");
		
		// ***************************internet***************************
		HashMap<String, Set<String>> http = new HashMap<String, Set<String>>();
		http.put( "package_name", new HashSet<String> (Arrays.asList("java.util.http")) );
		http.put( "method_name_or_sub_signature", new HashSet<String> (Arrays.asList("send")) );
		List<HashMap<String, Set<String>> > javaUtilHttpConjuct = Collections.singletonList(http);
		List<List<HashMap<String, Set<String>> > > javaUtilHttpDisjunct = Collections.singletonList(javaUtilHttpConjuct);
		List<List<List<HashMap<String, Set<String>> > > > javaUtilHttpScanner = Collections.singletonList(javaUtilHttpDisjunct);
		ScannerRule sr1 = createScannerRule(javaUtilHttpScanner, "internet");  // This can be wifi or carrier
		scb.addRules(sr1);
		
		// ***************************bluetooth***************************
		HashMap<String, Set<String>> test = new HashMap<String, Set<String>>();
		test.put( "class_name", new HashSet<String> (Arrays.asList("FullClassName")) );
		test.put( "method_name_or_sub_signature", new HashSet<String> (Arrays.asList("GiveMeFive")) );
		List<HashMap<String, Set<String>> > testConjuct = Collections.singletonList(test);
		List<List<HashMap<String, Set<String>> > > testDisjunct = Collections.singletonList(testConjuct);
		List<List<List<HashMap<String, Set<String>> > > > testScanner = Collections.singletonList(testDisjunct);
		ScannerRule sr2 = createScannerRule(testScanner, "bluetooth");  // This can be wifi or carrier
		scb.addRules(sr2);
		
		// ***************************nfc***************************
		HashMap<String, Set<String>> nfc = new HashMap<String, Set<String>>();
		nfc.put( "package_name", new HashSet<String> (Arrays.asList("android.app.nfc")) );
		nfc.put( "method_name_or_sub_signature", new HashSet<String> (Arrays.asList("send")) );
		List<HashMap<String, Set<String>> > nfcConjuct = Collections.singletonList(nfc);
		List<List<HashMap<String, Set<String>> > > nfcDisjunct = Collections.singletonList(nfcConjuct);
		List<List<List<HashMap<String, Set<String>> > > > nfcScanner = Collections.singletonList(nfcDisjunct);
		ScannerRule sr3 = createScannerRule(nfcScanner, "nfc");  // This can be wifi or carrier
		scb.addRules(sr3);
		return scb;
	}
}
