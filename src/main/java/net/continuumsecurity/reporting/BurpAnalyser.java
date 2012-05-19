package net.continuumsecurity.reporting;

import net.continuumsecurity.restyburp.model.ScanIssueBean;
import net.continuumsecurity.restyburp.model.ScanIssueList;
import net.continuumsecurity.Utils;

import org.apache.log4j.Logger;

public class BurpAnalyser {
	private static BurpAnalyser instance;
	Logger log = Logger.getLogger(BurpAnalyser.class);
	
	private BurpAnalyser() {
		
	}
	
	public static BurpAnalyser instance() {
		if (instance == null) {
			instance = new BurpAnalyser();
		}
		return instance;
	}
	
	public ScanIssueList filter(ScanIssueList issueList) {
		if (issueList.getIssues() == null) {
			log.info("No burp issues found");
			return issueList;
		}
		ScanIssueList ret = new ScanIssueList();
		for (ScanIssueBean issue : issueList.getIssues()) {
			ScanIssueBean filteredIssue = filterIssue(issue);
			if (filteredIssue == null) {
				log.info("Burp issue: "+issue.getIssueName()+" is a false positive.");
			} else {
				ret.getIssues().add(filteredIssue);
			}
		}
		return ret;
	}
	
	public ScanIssueBean filterIssue(ScanIssueBean issue) {
        log.info("Start Burp Issue filtering:");
		if ("Session token in URL".equalsIgnoreCase(issue.getIssueName())) {
			//If the session ID is not in the URL, then this is a false positive
			if (Utils.extractSessionIDName(issue.getIssueDetail()) == null) {
				log.info("session IDs not found in the burp detail, filterIssue() returning null. "+issue.getIssueDetail());
				return null;
			}
		}
		if ("Cookie without HttpOnly flag set".equalsIgnoreCase(issue.getIssueName())) {
			//This test is already defined in the session management scenario
            log.info("HttpOnly issue found, ignoring as it's already defined in a BDD test");
			return null;
		}
        /*
        if (issue.getIssueDetail().contains("xmlns XML attribute appears to be vulnerable to XML injection")) {
            log.info("Ignoring xmlns XML attribute false positive");
            return null;
        }
        if (issue.getIssueDetail().contains("The xmlns:soap XML attribute appears to be vulnerable to XML injection")) {
            log.info("Ignoring xmlns:soap attribute xml inj false positive");
            return null;
        }       */
        log.info("Stop Burp Issue filtering.");
		return issue;
	}
			
}
