#************************************************************************************#
#!/usr/bin/perl	
# Automated SCAP Security Tool - Vulnerabilities Test
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
use IO::File;        # supply object methods for filehandles
use warnings;        # gives control over which warnings are enabled
use Tie::File;       # used to append/tie date to config file
use XML::Twig;       # yum install perl-XML-Twig
use XML::LibXML;     # used to parse xml file
use Getopt::Long;    # xtended processing of command line options
use File::Basename;  # used to determine the name and path of the file
use Config::General; # used to parse conf file
#------------------------------------------------------------------------------------
#  Prototypes
#------------------------------------------------------------------------------------
sub getDistribution;       # Gets the OS distribution and version
sub getDatestring;         # Returns string with the day and time scan is performed
sub usage;                 # Function that prints out script help menu
sub appendReport;          # Append results to trend file
sub lookupCVSS;            # Parse the CVSS score for a CVE (if it exists)
sub vulnerabilities_Audit; # Run oscap depending on the OS
sub updateCVE;             # Update cve rules file
sub createReportFile;      # Create Last Run File
sub lookupSeverity;        # Search severity and crit cves of failed results
sub parse_severity;        # Get the severity of the failed test
sub parse_definiton;       # Get the definition id
sub parse_result;          # Get the result of the test
sub insertCritCVE;         # Insert into state file Crit CVEs
sub score_txt;             # Score severities through text
sub score_xml;             # Score severities through xml and cvss database
sub runOpenSCAP;           # Run openscap audit
sub runCISCAT;             # Run CIS-CAT audit
#------------------------------------------------------------------------------------
#  General Global variables
#------------------------------------------------------------------------------------
### Define path to configuration file
my $CONFIG_FILE = "/etc/scaptest/CheckScapStatus.cfg";
if (-f $CONFIG_FILE) {} # if config file was found pass
elsif (-f "/Program/Files/CheckScapStatus.cfg") {
    $CONFIG_FILE = "/Program/Files/CheckScapStatus.cfg";
}
else {
    die "ERROR: Config file not found. Review README for guidance"
}

my $CRONPATH = cwd(); # get current cron job path
die "ERROR: Cron path empty or not found." if ($CRONPATH eq "" ); # if path empty, die
#------------------------------------------------------------------------------------
#  General Global Excecutions and Variables
#------------------------------------------------------------------------------------
### Parse config file 
my $conf   = Config::General->new(-ConfigFile => $CONFIG_FILE,-AutoTrue => 1);
my %config = $conf->getall; # creates a hash with the elements from config file

### Create the report directory if it does not exist
my $WORKPATH = $config{"working_path"};
die "ERROR: Work path empty or not found." if ($WORKPATH eq "" ); # if path empty, die

my $REPORTPATH = $config{"report_path"}; # takes it from the config file
mkdir $REPORTPATH unless -d $REPORTPATH; # Check if dir exists. If not, create it. 

### Create the state file if it does not exist and save last audit percentage
my $STATE_FILE       = $REPORTPATH . $config{"vuln_state_file"};   # declare name of the state file
my $LASTRESULT_FILE  = $REPORTPATH . $config{"vuln_lastrun_file"}; # declare name of last run file
my $TRENDRESULT_FILE = $REPORTPATH . $config{"vuln_trend_file"};   # declare name of trending file
my $CRIT_CVES;                                                    # to store critical cves

### Creating State file
createStateFile();
my $state  = Config::General->new(-ConfigFile => $STATE_FILE,-AutoTrue => 1);
my %states = $state->getall; # creates a hash with the elements from state file
#------------------------------------------------------------------------------------
#  Nagios Global Variables
#------------------------------------------------------------------------------------
my $warn_threshold = $config{"vuln_default_warn"}; # default warn/crit values are taken from config file
$warn_threshold = 2 if ($warn_threshold eq "");    # default value if they are not initialized

my $crit_threshold = $config{"vuln_default_crit"}; # default warn/crit values are taken from config file
$crit_threshold = 5 if ($crit_threshold eq "");    # default value if they are not initialized

my @critical_cves  = split /, /, $config{"critical_cves"}; # critical cce's taken from config file
my ($RESULT_PERCENT, $NAGIOS_OUTPUT, $SEVERITIES_FILE);    # result percentage, failures, nagios output, severities file

### Default values for warn and crit can be changed here
GetOptions(
    "w|warn=s" => \$warn_threshold, # from config file: integer to initialize warning parameter
    "c|crit=s" => \$crit_threshold, # from config file: integer to initialize crit parameter
    "h|help"   => \&usage,          # subroutine defined below
);

### Sanitize basic user input values
die "Warning value must be larger than critical value\n" if ($warn_threshold > $crit_threshold);

### Create a hash that stores quantity and severity of test results from score_txt
my %results;

### Stores critical cves score
my $CVE_fails = 0;
#------------------------------------------------------------------------------------
#  Global Variables for Vulnerabilities Audit Subroutine and Excecution
#------------------------------------------------------------------------------------
my $DATE = getDatestring(); # current date and time string
my ($DISTRIBUTION, $VERSION) = ($states{"distribution"},$states{"version"}); 
my $CONFIGDIS = $states{"distribution"} . $states{"version"};
my $VULNERAB_RESULTS_FILENAME = $REPORTPATH . "$CONFIGDIS-vuln-audit-" . $DATE;  # name of the resulting file
my $OSCAP_VULN_RESULTS; # stores OpenSCAP results

### To work with the createCentosCVE()
my $parser; # to parse xml file
my $xpc;    # to obtain attributes from file
my $dom;    # the domain of the file

### Define Scoring Method
# Some operating systems do not have severities in their resulting files
# so they have to be searched in the CVSS database
my $FIND_CVSS = 0; # If this is true, CVSS scores for vulnerabilities will be downloaded from Novell

### Excecute Vulnerabilities audit depending on the OS
# This option can be changed in the config file. In case you get to use the tool in other
# OS that is not included in the version of this script, just add the OS to the variable
# given in the config file. This will translate that variable into an array and do a match.

# Specify audit tool in config file
my $audit_tool = $config{"vuln_audit_tool"};
die "Need to specify audit tool at config file." if (!$audit_tool);

# Store in array variable from config file that states compatibility 
# between the OS and the audit tool. Example: If freebsd is not in 
# openscap_compliant, is because openscap cannot be used by this script,
# or is not compliant yet in freebsd.
my @openscap_compliant = split /, /, $config{"vuln_openscap_compliant"}; # supported by OpenSCAP
my @ciscat_compliant   = split /, /, $config{"vuln_ciscat_compliant"};   # supported by CIS-CAT

# Hash with tool and supported OS
my %tool_compatibility = (
    "OpenSCAP" => \@openscap_compliant,
    "CIS-CAT"  => \@ciscat_compliant,
);
# Bool variable to store if tool is compliant with audited OS
my $os_compliant = grep /$DISTRIBUTION/, @{$tool_compatibility{$audit_tool}};

# Statement to select tool and execute command
if ( $tool_compatibility{"$audit_tool"} ) {
    # if tool is supported by OS and is openscap, execute audit
    if ( $audit_tool eq "OpenSCAP" && $os_compliant ) {
        vulnerabilities_Audit(); # run OpenSCAP
    }
    # if tool is supported by OS and is cis-cat, execute audit
    elsif ($audit_tool eq "CIS-CAT" && $os_compliant ) {
        runCISCAT(); # sub that executes audit
    }
    # tool matched in config file is not supported
    else {
        die "Current OS is not supported by this tool. Change tool in config file.";
    }
}
# In case tool is spelled incorrectly or it is not supported
else {
    die "Tool not supported by this program. Verify Config File.";
}

### Variables to report to Nagios
my $fails;     # quantity of vulnerabilities
my %xml_tests; # hash to save cves and their result, used in score_xml

### Determining scoring method
# This is used because some operating systems do not have the severities information
# so it has to be searched in the CVSS database
if ($FIND_CVSS) {
    score_xml(); # use cvss function
}
else { 
    score_txt(); # use txt function
} 
#------------------------------------------------------------------------------------
#  Report to Nagios
#------------------------------------------------------------------------------------
### Total report of the audit
my $report = "Score $fails Vulnerabilities ";

# Append to report the keys with their results
foreach my $mykey (sort keys %results) {
    $report .= "$results{$mykey}-$mykey ";
}
# Append to report critical rules results
$report .= "Crit CVEs: $CVE_fails-fail.\n";

### Delete duplicate files
createReportFile();

### Append report to trend file
appendReport();

### Insert Crit CVEs to state file
insertCritCVE();

### Delete files if it is selected in config file
unlink "$VULNERAB_RESULTS_FILENAME.html" if (!$config{"save_html"});
unlink "$VULNERAB_RESULTS_FILENAME.xml"  if (!$config{"save_xml"});

### Send score to Nagios
if ($fails >= $crit_threshold) {
    print (($NAGIOS_OUTPUT ? "CRIT: " : "SCAP CRIT - ") . $report);
}
elsif ($fails >= $warn_threshold) {
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
    my @rpm_linux_distributions = ("centos", "redhat", "sles", "suse");
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
        $distro  = "solaris";                             # set distribution
        $version = `uname -v | cut -d. -f1 | tr -d '\n'`; # set version
    }
    # Method #5 - If it is a windows device
    elsif ($^O eq "MSWin32") { 
        ($distro, $version) = ("windows", $Config{osvers}); 
    }
    # If device has not being added to the function
    else { 
        die "Can't recognize OS. Verify getDistribution sub capabalities." 
    }
    return $distro, $version; # returns the distribution and version
}
#------------------------------------------------------------------------------------
# SUB: Generate a date string
sub getDatestring {
    my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime();
    $mon += 1;
    $year += 1900;
    my $datestring = sprintf("%04d%02d%02d_%02d%02d%02d",
        $year, $mon, $mday, $hour, $min, $sec);
    return $datestring;
}
#------------------------------------------------------------------------------------
sub createStateFile {
    no warnings 'uninitialized'; # ignore uninitialized errors
    # open and creates file, if file empty, initialize with default value
    open my $stateFile, ">>", "$STATE_FILE" or die "Can't open or create $STATE_FILE\n";
    if (-z $stateFile) {
        my ($distribution, $version) = getDistribution(); 
        print $stateFile "distribution = $distribution\nversion = $version\n";
        print $stateFile "Crit_CVEs = None\n";
    }
    close $stateFile;
    `chmod 600 $STATE_FILE`; # add root permissions to file
    return; 
}
#------------------------------------------------------------------------------------
# SUB: Insert new percentage to state file
sub insertCritCVE { 
    my $posCVE = 2; # position where current cve's are located at the state file
    no warnings 'uninitialized'; # ignore uninitialized errors
    tie my @lines, 'Tie::File', "$STATE_FILE" or die "Cannot tie $STATE_FILE: $!"; # tie lines from file to array

    my @CVEline_str   = split / /, $lines[$posCVE]; # to store the splitted line results
    if ($CRIT_CVES ne "") {                               # case where there are critical cves
        $lines[$posCVE] = "$CVEline_str[0] = $CRIT_CVES"; # assign critical cves to line
    }
    else {                                                # case where there are critical cves
        $lines[$posCVE] = "$CVEline_str[0] = None";       # assign none to critical cves to line
    }
    untie @lines; # unlink array from file and write new percentage
}
#---------------------------------------------------------------------------------------------------------#
# SUB: Performs the oscap or ciscat vulnerabilities audit based in the operating system found.
# It creates a file with the results that will later be processed in order to send the info to Nagios.
sub vulnerabilities_Audit {	
    if ( $DISTRIBUTION eq "centos" ) {
        # severities are found in the resulting xml file
        $OSCAP_VULN_RESULTS = runOpenSCAP("$config{\"$DISTRIBUTION\_cve_filename\"}.bz2", $config{"$DISTRIBUTION\_cve_link"}, "centos$VERSION-cve-oval.xml");		
        $SEVERITIES_FILE = "$VULNERAB_RESULTS_FILENAME.xml";
    }
    elsif ( $DISTRIBUTION eq "redhat" ) {
        # severities are found in the general rhel file
        $OSCAP_VULN_RESULTS = runOpenSCAP("$config{\"redhat_cve_filename\"}.bz2", $config{"redhat_cve_link"}, $config{"redhat_cve_filename"});
        $SEVERITIES_FILE = $WORKPATH . $config{"redhat_cve_filename"};
    }
    elsif ( $DISTRIBUTION eq "suse" || $DISTRIBUTION eq "sles") {   
        # uses the cvss database to search for its severities
        $OSCAP_VULN_RESULTS = runOpenSCAP($config{"$CONFIGDIS\_cve_filename"}, $config{"$CONFIGDIS\_cve_link"}, $config{"$CONFIGDIS\_cve_filename"});
        $FIND_CVSS = 1; # use cvss method to search for severities		
    }
    elsif ( $DISTRIBUTION eq "debian" || $DISTRIBUTION eq "ubuntu" ) {   
        # debian has no severities found yet
        $OSCAP_VULN_RESULTS = runOpenSCAP($config{"$CONFIGDIS\_cve_filename"}, $config{"$CONFIGDIS\_cve_link"}, $config{"$CONFIGDIS\_cve_filename"});
        $SEVERITIES_FILE = $WORKPATH . $config{"$CONFIGDIS\_cve_filename"};
    }
    elsif ( $DISTRIBUTION eq "solaris" || $DISTRIBUTION eq "freebsd" ) {  
        # severities are found in the solaris version audit file - needs to be tested
        $OSCAP_VULN_RESULTS = runOpenSCAP($config{"$CONFIGDIS\_cve_filename"}, $config{"$CONFIGDIS\_cve_link"}, $config{"$CONFIGDIS\_cve_filename"});
        $SEVERITIES_FILE = $WORKPATH . $config{"$CONFIGDIS\_cve_filename"};
    }
    else {
        die "Operating System not supported by this script. Ask administrator to add it.";
    }
}
#------------------------------------------------------------------------------------
sub runOpenSCAP {	
    my ($cve_filename, $cve_link, $audit_file) = @_;
    updateCVE($cve_filename, $cve_link);

    # If it is centos, create centos cve from rhel feed
    if ("$DISTRIBUTION" eq "centos") {
        createCentosCVE($config{"redhat_cve_filename"});
    }
    my $OSCAPCOMMAND = "oscap oval eval --skip-valid --results $VULNERAB_RESULTS_FILENAME.xml " .
        "--report $VULNERAB_RESULTS_FILENAME.html " . $WORKPATH . $audit_file;
    my $audit_results = `$OSCAPCOMMAND`; # execute oscap command, store results in variable
    unlink "/tmp/oscap_cve.xml"; # unlink temporary file
    die "No XML results file found. OSCAP scan error." if (! -f "$VULNERAB_RESULTS_FILENAME.xml");
    return $audit_results;
}
#------------------------------------------------------------------------------------
### SUB: Run the ciscat tool
sub runCISCAT {
    # Specify and validate existance of cis-cat path
    die "ERROR: Did you add cis-cat? Can't find it." if ($config{"ciscat_path"} eq "" || !(-d $config{"ciscat_path"}));
    die "ERROR: Did you add java? Can't find it."    if ($config{"java_path"} eq "" || !(-f $config{"java_path"}));

    my $CISCATCOMMAND_VULN = "$config{java_path} -jar $config{ciscat_path}/CISCAT.jar -a " .
        "-up -va -x -r $REPORTPATH -rn $VULNERAB_RESULTS_FILENAME";
    system($CISCATCOMMAND_VULN); # run ciscat tool
    die "ERROR: No XML results file found. CISCAT scan error." if (! -f $REPORTPATH . "$VULNERAB_RESULTS_FILENAME.xml");
}
#------------------------------------------------------------------------------------
#SUB: Update CVE Package 
sub updateCVE {
    my ($oval_filename, $oval_link) = @_;
    chdir ($WORKPATH); # change to work path

    # Determine if there is a new version of the CVE feed (updated regularly)
    my $last_modified = "never";
    $last_modified = `date -r $oval_filename` if (-f $oval_filename); 

    # for to validate if file is corrupted or if failed to download
    my $wget_return;
    foreach my $try (0..5) {
        system("wget -c -N $oval_link -O $oval_filename");
        $wget_return = $?;
        if ($wget_return == 0) {
            last;
        }
        else {
            unlink $oval_filename;
            unlink "$oval_filename.bz2";
        }
    }
    # If file is new, unzip it
    my $new_modified = `date -r $oval_filename`;
    if ($last_modified ne $new_modified && substr($oval_filename, -3) eq "bz2") {
        system("bzip2 -dkf $oval_filename");
    }
    die "Could not find $oval_filename. Check network connection or file corruption." if (! -f "$oval_filename");
    chdir ($CRONPATH); # change to cron path, where script is running
}
#------------------------------------------------------------------------------------
# SUB: Search in CVE rules file the rule and its severity
sub lookupSeverity {
    my ($definition_id) = @_; # definition id
    my $severity_twig = XML::Twig->new( twig_roots =>
        { "oval_definitions/definitions/definition[\@id=\"$definition_id\"]/metadata/advisory" => \&parse_severity});
    $severity_twig->parsefile($SEVERITIES_FILE);
    $severity_twig->purge; # released memory
    return;
}
#------------------------------------------------------------------------------------
# SUB: Gets the severity value
sub parse_severity {
    my (undef, $element) = @_;
    my $severity = $element->first_child_text("severity");
    $results{ucfirst(lc($severity))} += 1; # increment severity
    my $cve = $element->first_child_text("cve"); # get cve id

    # each cve stated in the conf file 
    foreach my $crit_cve (@critical_cves){ 
        if ($cve eq $crit_cve){ 
            $CVE_fails++; # increment crit cve variable
            no warnings 'uninitialized'; # ignore uninitialized errors
            $CRIT_CVES .= "$cve "; # append crit cve id
        }
    }
    $element->purge; # release memory
    return;
}
#------------------------------------------------------------------------------------
# SUB: Gets the id of the test and its title
sub parse_definiton {
    my (undef, $element) = @_;
    my $definition = $element->att("id");
    my $CVE_name = $element->first_child("metadata")->first_child_text("title");
    $xml_tests{$definition} = [$CVE_name];
    $element->purge;
    return;
}
#------------------------------------------------------------------------------------
# SUB: Gets the result of certain definition
sub parse_result {
    my (undef, $element) = @_;
    my $definition = $element->att("definition_id");
    my $CVE_result = $element->att("result");
    push @{$xml_tests{$definition}}, $CVE_result;
    $element->purge;
    return;
}
#------------------------------------------------------------------------------------
sub score_txt {
    $OSCAP_VULN_RESULTS =~ s/Definition //g;            # cleaning openscap results
    $OSCAP_VULN_RESULTS =~ s/\nEvaluation done\.//;     # cleaning openscap results
    my @results     = split /\n/, $OSCAP_VULN_RESULTS;  # stores results in array
    my $total_tests = scalar @results; # defines the total number of verified tests

    # for to increment fails and look up for severities
    for my $result (@results) {
        my ($test, $testresult) = split /: /, $result; # split line into the test definition and true/false
        # The definition reports "true" if the system is vulnerable
        if ($testresult ne "false") {
            $fails++; # adds 1 to the severities counter
            lookupSeverity($test); # adds 1 to the severity found on %results, adds to crit cves
        }
    }
}
#------------------------------------------------------------------------------------
sub score_xml {
    # When XML parser notices one of the below patterns call the respective function
    my $twig = XML::Twig->new( twig_roots =>
    { "oval_results/oval_definitions/definitions/definition" => \&parse_definiton,
      "oval_results/results/system/definitions/definition"   => \&parse_result,
    });

    $twig -> parsefile("$VULNERAB_RESULTS_FILENAME.xml"); # parse result file

    # iterate over each CVE and sort by date
    for my $CVE_object (sort {$b->[0] cmp $a->[0]} values %xml_tests) {
        if ($CVE_object->[1] eq "true") {
            $fails++; # increment number of failed tests
            my $CVE = $CVE_object->[0]; # gets cve id
            foreach my $crit_cve (@critical_cves){ # each cve stated in the conf file 
                if ($CVE eq $crit_cve){ 
                    $CVE_fails++; # increment quantity of critical cves that failed
                    no warnings 'uninitialized'; # ignore uninitialized errors
                    $CRIT_CVES .= "$CVE "; # append cve id
                }
            }
            my $link = "https://web.nvd.nist.gov/view/vuln/detail?vulnId=$CVE"; # severities database link
            my $cvss = ""; # empty variable to store the severity
            $cvss = lookupCVSS($link); # returns the severity
            $results{$cvss} += 1; # increment the severity in the hash
        }
    }
}
#---------------------------------------------------------------------------------------------------------#
# SUB: Uses wget and regex to parse the CVSS score for a CVE (if it exists)
sub lookupCVSS {
    my ($link) = @_; # link with specific cve
    my $result = `wget -qO- $link`; # store html in variable
    # Parse severity from variable
    $result =~ m|.*https://nvd.nist.gov/cvss/v2-calculator.*/a>\s(\w+)|;
    my $cvss = ""; # variable to store result
    if ($1) {
        $cvss = ucfirst(lc($1)); # store severity result
    }
    else { 
        $cvss = "Unknown"; # if severity was not found send unknown
    } 
    return $cvss;
}
#---------------------------------------------------------------------------------------------------------#
# SUB: Append report to trend result file
sub appendReport {
    no warnings 'uninitialized'; # ignore uninitialized errors
    # open and creates file, if file empty, initialize with default value
    open my $fileHandle, ">>", "$TRENDRESULT_FILE" or die "Can't open or create $TRENDRESULT_FILE\n";
    if (-z $fileHandle) { 
        print $fileHandle "$DATE $report"; 
        `chmod 600 $TRENDRESULT_FILE`;
    }
    else {
        # tie lines from file to array
        tie my @lines, 'Tie::File', "$TRENDRESULT_FILE" or die "Cannot tie $TRENDRESULT_FILE: $!";
        if (scalar @lines >= $config{"vuln_trend_quant"}) {shift (@lines);} # removes first element if it is old enough
        else { push @lines, "$DATE $report"; }
        untie @lines; # unlink array from file and write new percentage
    }
    close $fileHandle;
}
#------------------------------------------------------------------------------------
### SUB: Create last result file
sub createReportFile {
    open my $fileHandle, ">>", $LASTRESULT_FILE or die "Can't open or create $LASTRESULT_FILE.";
    if (-z $fileHandle) { 
        print $fileHandle $report; 
        `chmod 600 $LASTRESULT_FILE`; # give root permissions to file
    }
    else {
        tie my @lines, 'Tie::File', $LASTRESULT_FILE or die "Cannot tie $LASTRESULT_FILE: $!";
        $lines[0] = $report;
        untie @lines; # unlink array from file and write new percentage
    }
    close $fileHandle;
}
#------------------------------------------------------------------------------------
# SUB: Written by Graham Mosley and edited by Jordan Caraballo Vega
# Creates centos 6 and 7 CVE to excecute vulnerabilities audit on oscap
sub createCentosCVE {

        my ($OVALEXT_FILENAME) = @_;
        $OVALEXT_FILENAME = $WORKPATH . $OVALEXT_FILENAME;

        my $file_date = `date +\%D -r $OVALEXT_FILENAME`; # date when file was downloaded
        my $current_date = `date +\%D`; # current date

        return if ($file_date ne $current_date && -f $WORKPATH . "centos$VERSION-cve-oval.xml"); # if file was not edited, dont make centos cve file
        # Initialize LibXML. We do this here because the RHEL_CVE file is used for both
        # creating a CentOS CVE file and for looking of the serverity of vulnerabilities
        # Create parser and load in DOM of RHEL CVE feed
        $parser = XML::LibXML->new();                   # parser object created
        $dom = $parser->parse_file("$OVALEXT_FILENAME");  # parsing the file obtained from RHEL mirror
        $dom->indexElements();                                  # take elements from the file

        # We must define namespaces in order to use XPath Queries
        $xpc = XML::LibXML::XPathContext->new;
        $xpc->registerNs('o', 'http://oval.mitre.org/XMLSchema/oval-definitions-5');
        $xpc->registerNs('r', 'http://oval.mitre.org/XMLSchema/oval-definitions-5#linux');

        # Find all packages whose srpms have been modified my centos
        my $pkgs = `rpm -qa --queryformat '%{NAME}:%{RELEASE}\n' | grep el$VERSION.centos | cut -d':' -f1`;
        my @changed_packages = split /\n/, $pkgs;

        # Scan through every OVAL object (package name) and make note of all object
        # ids that were modified by centos
        my @object_nodes = $xpc->findnodes('/o:oval_definitions/o:objects/r:rpminfo_object', $dom);
        my @object_ids = ();
        foreach my $node (@object_nodes) {
            my $object_id = $node->getAttribute("id");
            my $package_name = $node->getChildrenByTagName("name")->string_value;
            if ($package_name ~~ @changed_packages) {
                push @object_ids, $object_id;
            }
        }
        # Iterate through every OVAL test and collect the OVAL State ids referenced
        # in all tests that use one of the previously identified OVAL objects
        my @state_ids = ();
        my @test_nodes = $xpc->findnodes('/o:oval_definitions/o:tests/r:rpminfo_test', $dom);
        #print "DEBUG: checking test_nodes\n";
        foreach my $node (@test_nodes) {
            # $object_node has to search for children by a tag name that includes
        # any attached namespace (prior versions of the input file did not have a namespace attached).
            my $object_node = $node->getChildrenByTagName("red-def:object")->get_node(1);
            my $comment = $node->getAttribute("comment") || '';
            my $ref = $object_node->getAttribute("object_ref");
        # print "DEBUG: test '" . $comment . "' -> '" . $ref . "'\n";
            if ($object_node->getAttribute("object_ref") ~~ @object_ids) {
                my $state_node = $node->getChildrenByTagName("state")->get_node(1);
                my $state_id = $state_node->getAttribute("state_ref");
                push @state_ids, $state_id;
            }
        }

        # Iterate through every OVAL state checking if the id is related to a centos
        # modified package. If it is and the value contains .el6_\d replace it
        # with .el6
        my @state_nodes = $xpc->findnodes('/o:oval_definitions/o:states/r:rpminfo_state', $dom);
        foreach my $node (@state_nodes) {
            my $state_id = $node->getAttribute("id");
            if ($state_id ~~ @state_ids) {
                my $state_node = $node->getChildrenByTagName("evr")->get_node(1);
                if ($state_node) {
                    $state_node = $state_node->firstChild;
                    my $version_string = $state_node->textContent;
                    if ($version_string =~ /\.el$VERSION\_\d$/) {
                        $version_string =~ s/\.el$VERSION\_\d$/\.el$VERSION/;
                        changeTextNode($state_node, $version_string);
                    }
                }
            }
        }

        if ($VERSION eq 6)
        {
        # The oval feed has two different OVAL tests for RHEL/CentOS6
        my $rhel_test_xpath = '/o:oval_definitions/o:tests/r:rpminfo_test[@id="oval:com.redhat.rhsa:tst:20100842002"]';
        #my $rhel_test2_xpath = '/o:oval_definitions/o:tests/r:rpminfo_test[@id="oval:com.redhat.rhsa:tst:20111694002"]';
        my $rhel_test_node = $xpc->findnodes($rhel_test_xpath, $dom)->get_node(1);
        #my $rhel_test2_node = $xpc->findnodes($rhel_test2_xpath, $dom)->get_node(1);

        $rhel_test_node->removeChildNodes();
        $rhel_test_node->addNewChild(undef, "object")->setAttribute("object_ref", "oval:org.open-scap.cpe.redhat-release:obj:3");
        $rhel_test_node->addNewChild(undef, "state")->setAttribute("state_ref", "oval:org.open-scap.cpe.rhel:ste:1007");

        #$rhel_test2_node->removeChildNodes();
        #$rhel_test2_node->addNewChild(undef, "object")->setAttribute("object_ref", "oval:org.open-scap.cpe.redhat-release:obj:3");
        #$rhel_test2_node->addNewChild(undef, "state")->setAttribute("state_ref", "oval:org.open-scap.cpe.rhel:ste:1007");

    # Add the CentOS 6 state referenced in the RHEL6/CentOS6 test
    # Add the CentOS 6 state referenced in the RHEL6/CentOS6 test
    my $xml_centos_state = <<'    END_XML';
    <rpminfo_state id="oval:org.open-scap.cpe.rhel:ste:1007" version="1" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
      <name operation="pattern match">^centos-release</name>
      <version operation="pattern match">^6</version>
    </rpminfo_state>
    END_XML
    my $centos_state_xpath = "/o:oval_definitions/o:states";
    insertXML($centos_state_xpath, $xml_centos_state);

    # Add the CentOS object referenced in the RHEL/CentOS test
    my $xml_centos_object = <<'    END_XML';
    <rpminfo_object id="oval:org.open-scap.cpe.redhat-release:obj:3" version="1" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
      <name>centos-release</name>
    </rpminfo_object>

    END_XML
    my $centos_object_xpath = "/o:oval_definitions/o:objects";
    insertXML($centos_object_xpath, $xml_centos_object);

        # Find the RHEL6 gpg signing key and replace it with the CentOS6 key
        my $signing_xpath = '/o:oval_definitions/o:states/r:rpminfo_state[@id="oval:com.redhat.rhsa:ste:20100842001"]/*[local-name()="signature_keyid"]';
        my $signing_node = $xpc->findnodes($signing_xpath, $dom)->get_node(1)->firstChild;
        changeTextNode($signing_node, "0946fca2c105b9de");
        }

        elsif ($VERSION eq 7)
        {
    # Replace the RHEL7 test with a CentOS7 test
    my $rhel_test_xpath = '/o:oval_definitions/o:tests/r:rpminfo_test[@id="oval:com.redhat.rhsa:tst:20140675002"]';;
    my $rhel_test_node = $xpc->findnodes($rhel_test_xpath, $dom)->get_node(1);

    $rhel_test_node->removeChildNodes();
    $rhel_test_node->addNewChild(undef, "object")->setAttribute("object_ref", "oval:org.open-scap.cpe.redhat-release:obj:3");
    $rhel_test_node->addNewChild(undef, "state")->setAttribute("state_ref", "oval:org.open-scap.cpe.rhel:ste:1007");

    # Add the CentOS 7 state referenced in the RHEL6/CentOS6 test
    my $xml_centos_state = <<'    END_XML';
    <rpminfo_state id="oval:org.open-scap.cpe.rhel:ste:1007" version="1" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
      <name operation="pattern match">^centos-release</name>
      <version operation="pattern match">^7</version>
    </rpminfo_state>
    END_XML
    my $centos_state_xpath = "/o:oval_definitions/o:states";
    insertXML($centos_state_xpath, $xml_centos_state);

    # Add the CentOS object referenced in the RHEL/CentOS test
    my $xml_centos_object = <<'    END_XML';
    <rpminfo_object id="oval:org.open-scap.cpe.redhat-release:obj:3" version="1" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
      <name>centos-release</name>
    </rpminfo_object>
    END_XML

    my $centos_object_xpath = "/o:oval_definitions/o:objects";
    insertXML($centos_object_xpath, $xml_centos_object);


    # Find the redhat2 gpg signing key and replace it with the CentOS7 key
    my $signing_xpath = '/o:oval_definitions/o:states/r:rpminfo_state[@id="oval:com.redhat.rhsa:ste:20100842001"]/*[local-name()="signature_keyid"]';
    my $signing_node = $xpc->findnodes($signing_xpath, $dom)->get_node(1)->firstChild;
    changeTextNode($signing_node, "24c6a8a7f4a80eb5");
        }

        # save the file
        $dom->toFile($WORKPATH . "centos$VERSION-cve-oval.xml", 1);

        # Helper function to replace text in a given node
        sub changeTextNode {
            my ($node, $new_text) = @_;
            my $new_text_node = XML::LibXML::Text->new($new_text);
            $node->replaceNode($new_text_node);
            return;
        }

        # helper function for adding a string of XML to an XPath
        sub insertXML {
            my ($xpath, $xml_to_insert) = @_;
            my $parent_node = $xpc->findnodes($xpath, $dom)->get_node(1);
            my $insert_node = $parser->parse_string($xml_to_insert)->documentElement;
            $parent_node->addChild($insert_node);
            return;
        }
        return;
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
