#************************************************************************************#
#!/usr/bin/perl	
# Automated SCAP Security Tool - Baseline and Compliance Test
# June 6, 2016 - August 12, 2016
# Author: Jordan Alexis Caraballo-Vega - University of Puerto Rico at Humacao
# Co-Author: Graham Mosley - University of Pennsylvania
# Mentors: George Rumney, John Jasen
#------------------------------------------------------------------------------------
#  Imports
#------------------------------------------------------------------------------------
use Cwd;
use strict;          # disables expressions that could behave unexpectedly or are difficult to debug
use Config;          # access Perl configuration information
use IO::File;		 # supply object methods for filehandles
use warnings;        # gives control over which warnings are enabled
use Tie::File;       # used to append/tie date to config file
use XML::Twig;       # used to parse xml files
use Getopt::Long;    # xtended processing of command line options
use File::Basename;  # used to determine the name and path of the file
use Config::General; # used to parse conf file
#------------------------------------------------------------------------------------
#  Prototypes
#------------------------------------------------------------------------------------
sub getDistribution; # Gets the OS distribution and version
sub getDatestring;   # Returns string with the day and time scan is performed
sub createStateFile; # Creates state, if not present; takes last run percentage
sub usage;           # Function that prints out script help menu
sub inputSanitation; # Verify user nagios ranges inputs
sub insertPercentage;# Insert new percentage to state file
sub appendReport;    # Append results to trend file
sub runCISCAT;       # Executes CIS-CAT command
sub runOSCAP;        # Executes OSCAP command
sub createReportFile;# Creates Last Run File
sub parse_score;     # Parse score from resulting xml file
sub parse_rule;	     # Parse rule from resulting xml file
#------------------------------------------------------------------------------------
#  General Global variables
#------------------------------------------------------------------------------------
### Config file path
my $CONFPATH = "/etc/scaptest"; # path where config file is located                				 
die "I don't know where I am\n" if ($CONFPATH eq "" ); # if path empty, die
my $CONFIG_FILENAME          = $CONFPATH . "/CheckScapStatus.cfg"; 
#------------------------------------------------------------------------------------
#  General Global Excecutions and Variables
#------------------------------------------------------------------------------------
### Detect if config file is at the predetermined path
die "ERROR: $CONFIG_FILENAME not found." if (! -f $CONFIG_FILENAME);

### Parse config file 
my $conf = Config::General->new(
    -ConfigFile => $CONFIG_FILENAME,
    -AutoTrue   => 1
);
my %config = $conf->getall; # creates a hash with the elements

### Determine distribution and version of the system
my ($DISTRIBUTION, $VERSION) = getDistribution();         # OS variable, subroutine below
my $CONFIGDIS                = $DISTRIBUTION . $VERSION;  # used to search elements in conf file

### Create the report directory if it does not exist
my $WORKPATH = $config{"working_directory"};

# If path is empty, kill program
die "ERROR: Don't know where I am\n" if ($WORKPATH eq "" );

my $SAVINGDIR = $config{"report_directory"}; # takes it from the config file
mkdir $SAVINGDIR unless -d $SAVINGDIR;       # Check if dir exists. If not, create it. 

### Create the state file if it does not exist and save last audit percentage
my $STATE_FILE       = $SAVINGDIR . $config{"base_state_file"};   # declare name of the state file
my ($CURRENT_PERCENT, $LOWER_PERCENT)  = createStateFile();       # creates state file, gets percentage
my $CRIT_CCES;                                                    # to store critical cces
my $LASTRESULT_FILE  = $SAVINGDIR . $config{"base_lastrun_file"}; # declare name of last run file
my $TRENDRESULT_FILE = $SAVINGDIR . $config{"base_trend_file"};   # declare name of trending file
#------------------------------------------------------------------------------------
#  Nagios Global Variables
#------------------------------------------------------------------------------------
my $warn_threshold = $config{"base_default_warn"}; # default warn/crit values are taken from config file
$warn_threshold = 79 if ($warn_threshold eq "");   # if value is not initialized set default

my $crit_threshold = $config{"base_default_crit"}; # default warn/crit values are taken from config file
$crit_threshold = 69 if ($crit_threshold eq "");   # if value is not initialized set default

my @critical_cces  = split /, /, $config{"critical_cces"}; # critical cce's taken from config file
my ($RESULT_PERCENT, $fails, $NAGIOS_OUTPUT); # result percentage, failures, nagios output variable

### Default values for warn and crit can be changed here
GetOptions(
    "w|warn=s" => \$warn_threshold, # from config file: integer to initialize warning parameter
    "c|crit=s" => \$crit_threshold, # from config file: integer to initialize crit parameter
    "h|help"   => \&usage,          # subroutine defined below
);

### Sanitize basic user input values
die "Warn threshold must be between 0 and 100\n"  if ($warn_threshold < 0 || $warn_threshold > 100);
die "Crit threshold must be between 0 and 100\n"  if ($crit_threshold < 0 || $crit_threshold > 100);
die "Warn value must be larger than Crit value\n" if ($warn_threshold < $crit_threshold);

### Hash that stores quantity and severity of test results
my %results = (
    "pass"    => 0,
    "Unknown" => 0,
    "Other"   => 0,
);

### Hash that stores critical cces results
my %cce_results = (
    "fail"  => 0,
    "other" => 0,
);
#------------------------------------------------------------------------------------
#  Global Variables for Baseline Audit Subroutine and Excecution
#------------------------------------------------------------------------------------
my $DATE = getDatestring(); # function to get date string
my $BASELINE_RESULTS_FILENAME = "$CONFIGDIS-base-audit-" . $DATE; # name of the resulting file
my $BASE_OSCAP_HTML_REPORT    = $config{"save_html"} ? "--report $SAVINGDIR" . "$BASELINE_RESULTS_FILENAME.html" : "";

### Determine what tool to use depending the OS
# This option can be changed in the config file. In case you get to use the tool in other
# OS that is not included in the version of this script, just add the OS to the variable
# given in the config file. This will translate that variable into an array and do a match.

# Specify audit tool in config file
my $audit_tool = $config{"baseline_audit_tool"};
die "Need to specify audit tool at config file." if (!$audit_tool);

# Store in array variable from config file thats states compatibility 
# between the OS and the audit tool. Example: If freebsd is not in 
# openscap_compliant, is because openscap cannot be used by this script,
# or is not compliant yet in freebsd.
my @openscap_compliant = split /, /, $config{"openscap_compliant"}; # supported by OpenSCAP
my @ciscat_compliant   = split /, /, $config{"ciscat_compliant"};   # supported by CIS-CAT
my @stig_compliant     = split /, /, $config{"stig_compliant"};     # still in development

# Hash with tool and supported OS
my %tool_compatibility = (
    "OpenSCAP" => \@openscap_compliant,
    "CIS-CAT"  => \@ciscat_compliant,
    "STIG"     => \@stig_compliant,
);

# Bool variable to store if tool is compliant with audited OS
my $os_compliant = grep /$DISTRIBUTION/, @{$tool_compatibility{$audit_tool}};

# Statement to select tool and execute command
if ( $tool_compatibility{"$audit_tool"} ) {
    # if tool is supported by OS and is openscap, execute audit
    if ( $audit_tool eq "OpenSCAP" && $os_compliant ) {
        runOSCAP(); # sub that executes audit
    }
    # if tool is supported by OS and is cis-cat, execute audit
    elsif ($audit_tool eq "CIS-CAT" && $os_compliant ) {
        runCISCAT(); # sub that executes audit
    }
    # if tool is supported by OS and is openscap, die because it needs implementation
    elsif ($audit_tool eq "STIG" && $os_compliant ) {
        die "STIG Needs to be implemented";
    }
    # tool matched in config file is not supported is not supported
    else {
        die "Current OS is not supported by this tool. Change tool in config file.";
    }
}
# In case tool is spelled incorrectly or it is not supported
else {
    die "Tool not supported by this program. Verify Config File.";
}
#------------------------------------------------------------------------------------
#  Report to Nagios
#------------------------------------------------------------------------------------
### When XML parser notices one of the below patterns call the respective function
my $twig = XML::Twig->new( twig_roots =>
    { "TestResult/rule-result" => \&parse_rule,
      "TestResult/score"       => \&parse_score,
    });

### Parse XML file
$twig -> parsefile($SAVINGDIR . "$BASELINE_RESULTS_FILENAME.xml");

### Add the total of tests performed
my $num_tests = 0; # store preliminar sum of hash
foreach my $myvalue (values %results) {
	$num_tests += $myvalue;
}

### Add the total of tests failed
my $num_failures = $num_tests - $results{"pass"};

### Total report of the audit
my $report = "Score $RESULT_PERCENT% ($results{pass}/$num_tests passed) ";

# Append to report the keys with their results
foreach my $mykey (sort keys %results) {
    $report .= "$results{$mykey}-$mykey " if ($mykey ne "pass");
}

# Append to report critical rules results
$report .= "Crit CCEs: $cce_results{fail}-fail $cce_results{other}-other.\n";

### Store result in file
createReportFile();

### Insert percentage to state file
insertPercentage();

### Append report to trend file
appendReport();

### Delete files if it is selected in config file
unlink $SAVINGDIR . "$BASELINE_RESULTS_FILENAME.html" if (!$config{"save_html"});
unlink $SAVINGDIR . "$BASELINE_RESULTS_FILENAME.xml"  if (!$config{"save_xml"});

### Print report
if ($RESULT_PERCENT <= $crit_threshold) {
    print (($NAGIOS_OUTPUT ? "CRIT: " : "SCAP CRIT - ") . $report);
} 
elsif ($RESULT_PERCENT <= $warn_threshold) {
    print (($NAGIOS_OUTPUT ? "WARN: " : "SCAP WARN - ") . $report);
} 
else {
    print (($NAGIOS_OUTPUT ? "OK: " : "SCAP OK - ") . $report);
}
#------------------------------------------------------------------------------------
#  Subroutines
#------------------------------------------------------------------------------------
### SUB: Gets the OS distribution through the linux module, OS can be added to this function
sub getDistribution {

    my ($distro, $version); # variables to store distribution and version

    # Method #1 - Get distribution and version through rpm command
    my @rpm_linux_distributions = ("centos", "redhat", "sles");
    my $rpm_command;

    foreach my $os (@rpm_linux_distributions) {
        $rpm_command = `rpm -qa | grep $os-release`;
        if ($rpm_command) {
            $rpm_command =~ /([0-9]+)/; # regex looking for first integer match
            return $os, $1;             # return distribution and version
        }
    }
    # Method #2 - Get distribution and version through cat /etc/*release command
    my @other_linux_distributions = ("debian", "ubuntu"); # other linux distributions
    my $release_command           = `cat /etc/*release`;  # log of release information

    if ($release_command) {
        my @clean_result = split(/[ ,="]/, $release_command); # splitting results into array
        foreach my $os (@other_linux_distributions) {
           if ( grep { lc $_ eq $os} @clean_result ) {
                $release_command =~ /([0-9]+)/; # regex looking for first integer match
                return lc $os, $1;              # return distribution and version
           }
       }
    }
    # Method #3 - If it is a FreeBSD device.
    elsif ($^O eq "freebsd") { 
        $distro  = "freebsd";                # set distribution
        $version = `uname -r | cut -d. -f1`; # set version
	}
    # Method #4 - If it is a Solaris device.
    elsif ($^O eq "solaris") { 
        $distro  = "solaris";                # set distribution
        $version = `uname -v | cut -d. -f1 | tr -d '\n'`; # set version
	}
	# Method #5 - If it is a windows device
	elsif ($^O eq "MSWin32") { 
		($distro, $version) = ($Config{osname}, $Config{osvers}); 
	}
	# If device has not being added to the function
	else { 
		die "Can't recognize OS. Verify getDistribution sub capabalities." 
	}
	return $distro, $version; # returns the distribution and version
}
#---------------------------------------------------------------------------------------------------------#
### SUB: Generate a date string
sub getDatestring {
    my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime();
    $mon += 1;
    $year += 1900;
    my $datestring = sprintf("%04d%02d%02d_%02d%02d%02d",
        $year, $mon, $mday, $hour, $min, $sec);
    return $datestring;
}
#------------------------------------------------------------------------------------
### SUB: Generate state file and get current percentage
sub createStateFile {
    no warnings 'uninitialized'; # ignore uninitialized errors
    # open and creates file, if file empty, initialize with default value
    open my $fileHandle, ">>", $STATE_FILE or die "Can't open or create $STATE_FILE";
    if (-z $fileHandle) {
        print $fileHandle "current_percentage = 0.00\n";
        print $fileHandle "lower_percentage = 0.00\n";
        print $fileHandle "Crit_CCEs = None\n";
        print $fileHandle "Nagios_Status = CRIT\n";
        close $fileHandle;
        `chmod 600 $STATE_FILE`; # add root permissions to file
        return 0.00, 0.00; 
	}

    # gets percentage from state file
    my $percentage      = `grep -oP '(?<=current_percentage = ).*' "$STATE_FILE"`;
    my $lowerPercentage = `grep -oP '(?<=lower_percentage = ).*' "$STATE_FILE"`;

    # Validate percentage format - it has to be a decimal
    die "$STATE_FILE does not have the requiered format." if (!($percentage =~ m/^\d+.\d+$/));

    return $percentage, $lowerPercentage;
}
#------------------------------------------------------------------------------------
### SUB: Insert new percentage to state file
sub insertPercentage { 
    my ($posPer, $posLow, $posCCE, $posState) = (0, 1, 2, 3); # position where current percentage is located at the state file
    no warnings 'uninitialized'; # ignore uninitialized errors
    tie my @lines, 'Tie::File', "$STATE_FILE" or die "Cannot tie $STATE_FILE: $!"; # tie lines from file to array

    my @Perline_str   = split / /, $lines[$posPer];   # to store the splitted line results
    my @Lowline_str   = split / /, $lines[$posLow];   # to store the splitted line results
    my @CCEline_str   = split / /, $lines[$posCCE];   # to store the splitted line results
    my @STATEline_str = split / /, $lines[$posState]; # to store the splitted line results

    if ($Perline_str[0] ne "current_percentage") {             # validate format of the file again
        die "$STATE_FILE does not have the requiered format."; # kill program to check state file format
    } 

    if ($RESULT_PERCENT < $CURRENT_PERCENT) {                    # case where new percentage diminishes
        $lines[$posLow]   = "$Lowline_str[0] = $RESULT_PERCENT"; # assign new percentage to lower % line
        $lines[$posState] = "$STATEline_str[0] = CRIT";          # assign CRIT status
	}
    elsif ($RESULT_PERCENT > $CURRENT_PERCENT) {                 # case where new percentage increases
        $lines[$posPer]   = "$Perline_str[0] = $RESULT_PERCENT"; # assign new percentage to result
        $lines[$posLow]   = "$Lowline_str[0] = 0.00";            # restore lower percentage to 0
        $lines[$posState] = "$STATEline_str[0] = WARN";          # assign WARN status
    }
    elsif ($RESULT_PERCENT == $CURRENT_PERCENT) {                # case where result is the same
        $lines[$posLow]   = "$Lowline_str[0] = 0.00";            # restore lower percentage to 0
        $lines[$posState] = "$STATEline_str[0] = OK";            # assign OK status
    }
    if ($CRIT_CCES ne "") {                                      # case where there are critical cces
        $lines[$posCCE] = "$CCEline_str[0] = $CRIT_CCES";        # assign critical cces to line
    }
    else {                                                       # case where there are no critical cces
        $lines[$posCCE] = "$CCEline_str[0] = None";              # assign none to the critical cces line
    } 
	untie @lines; # unlink array from file and write new percentage
}
#---------------------------------------------------------------------------------------------------------#
### SUB: Append report to trend result file
sub appendReport {
    no warnings 'uninitialized'; # ignore uninitialized errors
	# open and creates file, if file empty, initialize with default value
    open my $fileHandle, ">>", $TRENDRESULT_FILE or die "Can't open or create $TRENDRESULT_FILE\n";
    if (-z $fileHandle) { 
        print $fileHandle "$DATE $report"; 
        `chmod 600 $TRENDRESULT_FILE`; # give root permissions to file
    } 
    else {
        # tie lines from file to array
        tie my @lines, 'Tie::File', $TRENDRESULT_FILE or die "Cannot tie $TRENDRESULT_FILE: $!";

        # removes first element if it is old enough
        if (scalar @lines >= $config{"base_trend_quant"}) {
            shift (@lines);
        } 
        # push element to last index if there is space 
        else { 
            push @lines, "$DATE $report"; 
        } 
        untie @lines; # unlink array from file and write new percentage
    }
    close $fileHandle;
}
#------------------------------------------------------------------------------------
### SUB: Run the ciscat tool
sub runCISCAT {
    # More info: https://benchmarks.cisecurity.org/downloads/audit-tools/documents/CIS-CATUsersGuide_000.pdf
    my $CISCAT_XCCDF_FILE = $config{$CONFIGDIS . "_XCCDF_cis_file"};

    # If benchmark file was not specified exit
    die "No CISCAT Benchmark file given on config file." if (!$CISCAT_XCCDF_FILE);

    # In case of having the jdk package downloaded into the working directory
    my $CISCATCOMMAND_BASELINE =  $WORKPATH . "jdk1.8.0_91/bin/java  -jar CISCAT.jar -a " .
        "-b benchmarks/$CISCAT_XCCDF_FILE -l2 -x -r $SAVINGDIR -rn $BASELINE_RESULTS_FILENAME";

    # In case of having openJDK or java installed
    # my $CISCATCOMMAND_BASELINE =  "./CIS-CAT.sh -a " .
    #       "-b benchmarks/$CISCAT_XCCDF_FILE -l2 -x -r $SAVINGDIR -rn $BASELINE_RESULTS_FILENAME"; 

    chdir ($WORKPATH . "cis-cat-full"); # change to ciscat directory
    system($CISCATCOMMAND_BASELINE);    # run ciscat tool
    chdir ($WORKPATH);                  # change to work directory
    # if the txt results file doesn't exist exit with NAGIOS unknown error code
    die "No XML results file found. CISCAT scan error." if (! -f $SAVINGDIR . "$BASELINE_RESULTS_FILENAME.xml");
}
#------------------------------------------------------------------------------------
### SUB: Run openscap tool
sub runOSCAP {
    # More info: http://static.open-scap.org/openscap-1.0/oscap_user_manual.html
    my $OSCAP_XCCDF_FILE = $config{$CONFIGDIS . "_XCCDF_osc_file"};    # openscap xccdf file
    my $OSCAP_PROFILE    = $config{$CONFIGDIS . "_XCCDF_osc_profile"}; # openscap profile used with xccdf file

    # If benchmark file was not specified exit
    die "No OpenSCAP Benchmark file, or profile given on config file." if (!$OSCAP_PROFILE || !$OSCAP_XCCDF_FILE);

    my $OSCAPCOMMAND_BASELINE = "oscap xccdf eval --skip-valid --profile $OSCAP_PROFILE --results $SAVINGDIR".
        "$BASELINE_RESULTS_FILENAME.xml $BASE_OSCAP_HTML_REPORT $OSCAP_XCCDF_FILE > /dev/null";		

    system($OSCAPCOMMAND_BASELINE); # run oscap tool
    # if the txt results file doesn't exist exit with NAGIOS unknown error code
    die "No XML results file found. OSCAP scan error." if (! -f $SAVINGDIR . "$BASELINE_RESULTS_FILENAME.xml");
}
#------------------------------------------------------------------------------------
### SUB: Parse the certain rules found in the xml file
sub parse_rule {
    my (undef, $element) = @_;                         # receives the rule from the test
    my $severity = $element->att("severity");          # gets the severity value
    my $result = $element->first_child_text("result"); # gets the result
    my ($cce, $dirtycce);                              # used to get cce id with regular expressions

    # ingore unselected or info tests
    if ($result eq "notselected" or $result eq "info") {
        return;
    } 
    elsif ($result eq "pass") {
        $results{"pass"}++;
    } 
    elsif ($result eq "fail") {
        if (!$severity) {
            $severity = "Unknown";
        }

        $results{ucfirst(lc($severity))} += 1; # increment severity, add to hash if it is not there

        $cce = $element->first_child_text("ident"); # oscap format, gets cee id
		# if it is empty, is a ciscat id, so here is taken the ciscat rule id
        if ($cce eq "") { 
            $dirtycce  = $element->att("idref") =~ /_rule_(.*?)_/; # get the cce with regular expressions (CIS-CAT audit)
            $cce = $1; # the result of the dirtycce
        } 

        # each cce stated in the conf file
        foreach my $crit_cce (@critical_cces) {
            if ($cce eq $crit_cce){ 
                $cce_results{"fail"}++; # increment cces hash failures
                no warnings 'uninitialized'; # ignore uninitialized errors
                $CRIT_CCES .= "$cce "; # append cce id
            }
        }

    # it's possible that tests can produce other types of reports
    # the most common is notchecked which occurs when it's parent test failed
    } 
    else {
        $results{"other"}++; # increment as an other severity
        $cce = $element->first_child_text("ident"); # gets the cce id
        if ($cce eq "") { 
            $dirtycce  = $element->att("idref") =~ /_rule_(.*?)_/; # get the cce with regular expressions (CIS-CAT audit)
            $cce = $1; # the result of the dirtycce
        } 
	
        # each cce stated in the conf file
        foreach my $crit_cce (@critical_cces) { 
            $cce_results{"other"}++ if ($cce eq $crit_cce); # increment cce hash if cce did not failed but was unknown
        }
    }
    $element->purge; # release element from memory
    return;
}
#------------------------------------------------------------------------------------
### SUB: Parse score from the resulting xml file
sub parse_score {
    my (undef, $element) = @_; # receives element
    $RESULT_PERCENT = sprintf("%.2f",$element->first_child_text); # gets score
    return;
}
#------------------------------------------------------------------------------------
### SUB: Create last result file
sub createReportFile {
    # store in file the report line
    # create the last result file if it doesn't exist
    my $fh;
    if (! -f $LASTRESULT_FILE) {
        $fh = IO::File->new($LASTRESULT_FILE, "w");
        print $fh $report;
        $fh->close();
	} 
    else {
        unlink ($LASTRESULT_FILE);
        $fh = IO::File->new($LASTRESULT_FILE, "w");
        print $fh $report;
        $fh->close();
    }
    `chmod 600 $LASTRESULT_FILE`;
}
#------------------------------------------------------------------------------------
# SUB: In case of trying to print the different options that has the script
sub usage {
    print<<USAGE;

    This script is a wrapper for the OpenSCAP and CIS-CAT program.
    It was written to be used in conjunction with Nagios.
    The default values for warn and crit are defined in config.
    They can be overriden by a command line argument.

    Note: this script uses a config file (CheckScapStatus.cfg)  

    Usage Examples:
        $0
        $0   -w 90 -c 70
        $0   -h    # shows this information

    Options:
        -w | -warn
            Warn if score is less than this value.
        -c | -crit
            Crit if score is less than this value.
        -h
            This help and usage information
USAGE
    exit 3;
}
