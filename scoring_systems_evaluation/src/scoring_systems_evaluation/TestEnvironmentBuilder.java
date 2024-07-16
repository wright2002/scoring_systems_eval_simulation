package scoring_systems_evaluation;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.Scanner;

import repast.simphony.context.Context;
import repast.simphony.dataLoader.ContextBuilder;
import repast.simphony.engine.environment.RunEnvironment;
import repast.simphony.parameter.Parameters;
import repast.simphony.random.RandomHelper;
import repast.simphony.context.*;

public class TestEnvironmentBuilder implements ContextBuilder<Object> {

	@Override
	public Context build(Context<Object> context) {
		context.setId("scoring_systems_evaluation");
		
		// get absolute file path specified in runtime GUI
		Parameters params = RunEnvironment.getInstance().getParameters();
		String file_path = params.getString("source_file_path");
		
		// tracks vulns in environment
		int totalVulns = 0;
		
		// count number of rows in input csv file
		try {
			int count = 0;
			Scanner scanCount = new Scanner(new File(file_path));
			while(scanCount.hasNextLine()) {
		        scanCount.nextLine();
		        count++;
		    }
			
			// subtract one for header row
			totalVulns = count - 1;
			
			scanCount.close();
		} catch (FileNotFoundException e){
			System.out.println("error1");
			return context;
		}
		
		// parse input from csv file one line at a time
		try {
			Scanner scan = new Scanner(new File(file_path));
			scan.useDelimiter(",|\\r?\\n"); // delimiter is comma or end of line
			
			System.out.println(scan.nextLine());
			
			// parse out csv line
			// format is: 
			// ID (string), inKEV (boolean), date (double), CVSS (double), EPSS (double), MARIST (double)
			for (int i = 0; i < totalVulns; i++) {
				String cveNum = scan.next();
				boolean inKEV = scan.nextBoolean();
				double scoreRandom = RandomHelper.nextDoubleFromTo(0.0, 10.0);
				double date = scan.nextDouble(); // YYYYMMDD
				double scoreFIFO = 100000000 - date;
				double scoreLIFO = date;
				double scoreCVSS = scan.nextDouble() + (scoreFIFO / 1000000000); // FIFO tiebreaker
				double scoreEPSS = scan.nextDouble();
				double scoreMarist = scan.nextDouble() + (scoreFIFO / 1000000000 - 0.079); // FIFO tiebreaker with smaller decimal
				context.add(new VulnerabilityRandom(cveNum, scoreRandom, inKEV));
				context.add(new VulnerabilityFIFO(cveNum, scoreFIFO, inKEV));
				context.add(new VulnerabilityLIFO(cveNum, scoreLIFO, inKEV));
				context.add(new VulnerabilityCVSS(cveNum, scoreCVSS, inKEV));
				context.add(new VulnerabilityEPSS(cveNum, scoreEPSS, inKEV));
				context.add(new VulnerabilityMarist(cveNum, scoreMarist, inKEV));
			}
			scan.close();
		} catch (FileNotFoundException e){
			System.out.println("error2");
			return context;
		}
		
		
		// old code from proof of concept
		/*
		int kevVulnsNum = 70;
		int benignVulnsNum = totalVulns - kevVulnsNum;
		
		for (int i = 0; i < benignVulnsNum; i++) {
			int cveNum = RandomHelper.nextIntFromTo(0, 1000);
			double scoreRandom = RandomHelper.nextDoubleFromTo(0.0, 10.0);
			double scoreFIFO = RandomHelper.nextDoubleFromTo(0.0, 10.0);
			double scoreLIFO = RandomHelper.nextDoubleFromTo(0.0, 10.0);
			double scoreCVSS = RandomHelper.nextDoubleFromTo(0.0, 10.0);
			double scoreEPSS = RandomHelper.nextDoubleFromTo(0.0, 10.0);
			double scoreMarist = RandomHelper.nextDoubleFromTo(0.0, 10.0);
			context.add(new VulnerabilityRandom(cveNum, scoreRandom, false));
			context.add(new VulnerabilityFIFO(cveNum, scoreFIFO, false));
			context.add(new VulnerabilityLIFO(cveNum, scoreLIFO, false));
			context.add(new VulnerabilityCVSS(cveNum, scoreCVSS, false));
			context.add(new VulnerabilityEPSS(cveNum, scoreEPSS, false));
			context.add(new VulnerabilityMarist(cveNum, scoreMarist, false));
		}
		for (int i = 0; i < kevVulnsNum; i++) {
			int cveNum = RandomHelper.nextIntFromTo(0, 1000);
			double scoreRandom = RandomHelper.nextDoubleFromTo(0.0, 10.0);
			double scoreFIFO = RandomHelper.nextDoubleFromTo(0.0, 10.0);
			double scoreLIFO = RandomHelper.nextDoubleFromTo(0.0, 10.0);
			double scoreCVSS = RandomHelper.nextDoubleFromTo(0.0, 10.0);
			double scoreEPSS = RandomHelper.nextDoubleFromTo(0.0, 10.0);
			double scoreMarist = RandomHelper.nextDoubleFromTo(0.0, 10.0);
			context.add(new VulnerabilityRandom(cveNum, scoreRandom, true));
			context.add(new VulnerabilityFIFO(cveNum, scoreFIFO, true));
			context.add(new VulnerabilityLIFO(cveNum, scoreLIFO, true));
			context.add(new VulnerabilityCVSS(cveNum, scoreCVSS, true));
			context.add(new VulnerabilityEPSS(cveNum, scoreEPSS, true));
			context.add(new VulnerabilityMarist(cveNum, scoreMarist, true));
		}
		*/
		
		
		// add agents to remove vulns each tick
		context.add(new SecurityGuardRandom("random"));
		context.add(new SecurityGuardFIFO("FIFO"));
		context.add(new SecurityGuardLIFO("LIFO"));
		context.add(new SecurityGuardCVSS("CVSS"));
		context.add(new SecurityGuardEPSS("EPSS"));
		context.add(new SecurityGuardMarist("marist"));
		
		
		
		return context;
	}
}
