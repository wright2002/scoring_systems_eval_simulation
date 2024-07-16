scoring_systems_eval_simulation README

The directory "scoring_systems_evaluation" contains the full eclipse workspace
for the simulation model.

RePast Simphony uses its own eclipse application, which should be installed
with the toolkit online at https://repast.github.io/download.html


Directions for use:

Run the program from eclipse, and a GUI should appear.

There is no default dataset loaded, so switch to the "parameters" tab in the
lower left corner of the GUI.

In the input box labeled "Data file" and populated with "changeme", enter the
absolute file path to the dataset file.

The format for the dataset file (which has one header row) is: 
ID(string),inKEV(boolean),date(double),CVSS(double),EPSS(double),MARIST(double)

Once the data file parameter is set, the simulation is ready to be run.

It can be helpful to set run options such as tick delay to manage the output.
Setting run options only works once the simulation is initialized, so begin
with the power button before setting run options.

The output graph should appear on screen as the simulation is run.

The corresponding output file will be created in the eclipse workspace once
the simulation is stopped.

The output file will need to be further processed in order to yield the
exposure values, so use the python script "calculate_exposure", by
replacing the file names with the desired names.
