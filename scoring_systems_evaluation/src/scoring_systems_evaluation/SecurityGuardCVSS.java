package scoring_systems_evaluation;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import repast.simphony.context.Context;
import repast.simphony.engine.schedule.ScheduledMethod;
import repast.simphony.util.ContextUtils;

public class SecurityGuardCVSS {

	private String id;
	
	public SecurityGuardCVSS(String id) {
		this.id = id;
	}
	

	@ScheduledMethod(start = 1, interval = 1)
	public void step() {
		
		// import all CVSS vulnerabilities for review as Java Objects
		Context<Object> context = ContextUtils.getContext(this);
		
		Stream<Object> s = context.getObjectsAsStream(VulnerabilityCVSS.class);
		List<Object> remainingVulns = s.collect(Collectors.toList()); 
		
		
		double highestScore = 0.0;
		
		// find highest score remaining in environment and remove
		if (remainingVulns.size() > 0) {
			Object highestRiskVuln = remainingVulns.get(0);
			for (int i = 0; i < remainingVulns.size(); i++) {
				// use toString to subvert Java Object class typing
				if (Double.parseDouble(remainingVulns.get(i).toString()) > highestScore) {
					highestRiskVuln = remainingVulns.get(i);
					highestScore = Double.parseDouble(remainingVulns.get(i).toString());
				}
			}
			context.remove(highestRiskVuln);
		}
	}
}
