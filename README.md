# Automated SCAP Security Tool

- Tool to continuously monitor our operating systems.
- Compare and implement different security tools.
- Keep time trending record of the report.
- Identify specific critical rules.
- Report to Nagios.

## Getting Started

When executing the program for the first time you can run CopyFiles script to place in the specific directories the needed files to run the assessments. To check if it is working, you can run the cron job file. It is configured to run daily.

```
bash ./CopyFiles                 # will copy files in their default directories
/etc/cron.daily/RunBaseScapTest  # will execute baseline audit
/etc/cron.daily/RunVulnScapTest  # will execute vulnerability audit
```

### Prerequisites

#### Centos 6, Centos 7, RHEL 6 and RHEL 7      
```
yum install perl-XML-Twig perl-XML-LibXML perl-Config-General openscap-scanner scap-security-guide bzip2 wget unzip
```

#### SLES 11 and SLES 12               
```
zypper install perl-XML-Twig perl-XML-LibXML perl-Config-General openscap-content openscap-utils bzip2 wget
```
#### Ubuntu 14 and Ubuntu 16            
```
apt-get install xml-twig-tools libxml-twig-perl libxml-libxml-perl libconfig-general-perl libopenscap8 bzip2 wget
```
#### Debian 8       
```
apt-get install libconfig-general-perl libxml-twig-perl libxml-libxml-perl libopenscap8 bzip2 wget
```
#### Windows
Windows can be assessed by CIS-CAT baseline and vulnerabilities features.

## Running the assessments

These scripts support OpenSCAP and CIS-CAT assessment tools.

### OpenSCAP

The config file includes OpenSCAP as the default assessment tool. If the operating system is not supported by OpenSCAP, the program will die and output the requirements. For running openscap, you can simply execute the cronjob files as stated above, or run the files directly from lib.
```
/usr/local/lib/scaptest/BaseScapTest.pl # baseline test
/usr/local/lib/scaptest/VulnScapTest.pl # vulnerabilites test
```
### CIS-CAT

In order to run CIS-CAT you need to download it from their web page and extract it at the /usr/local/lib/scaptest directory. It needs openJDK installed in order to run. The current script is assuming that the jdk package is extracted in the working directory. In order to run this program specify where your java path is located.

At the moment CIS-CAT is set to a full auto assessment. In case you want to specify a specific benchmark file, add a line to the configuration file as it follows:
```
{operating_system}{version}_XCCDF_cis_file = {cis-cat_xccdf_file}
Example: centos6_XCCDF_cis_file = CIS_CentOS_Linux_6_Benchmark_v2.0.1-xccdf.xml
```
To download the CIS-CAT bundle you need a licence, however, it can be downloaded from https://community.cisecurity.org/collab/public/. The Oracle JDK package can be downloaded from http://www.oracle.com/technetwork/java/javase/downloads/jdk8-downloads-2133151.html?ssSourceSiteId=otnes.

## Output

The program will produce by default:
  * State file - will keep some variables from the system
  * Last result file - will keep the last result of the audit
  * Trending file - will keep a number of results from previous assessments
  * HTML result (turn save_html = true in config file)
  * XML result (turn save_html = true in config file)
```
hostname SCAP WARN - Score 85% (123/145) 2-High 3-Medium 2-Low Crit CCEs: 0-fail     # baseline
hostname SCAP CRIT - Score 7 Vulnerabilities 2-High 3-Medium 2-Low Crit CVEs: 0-fail # vulnerabilities
```
The script WindowsCISAnalyze.py lets the admin summarize scores from CIS-CAT Windows baseline and vulnerabilities assessments. This file is a separate script that needs to be ran manually but it can be scheduled by a cron job. The output file looks like:
```
Date CIS-CAT Vulnerability Assessment - Last Updated On Wednesday, May 17 2017 00:09:56
Host: SCAPTEST, OS: Windows 8, Score: 867 Vulnerabilities 741-High 102-Medium 17-Low
Host: SCAPTEST, OS: Windows 8, Score: 767 Vulnerabilities 641-High 102-Medium 17-Low
WARN: The number of scores 8 is less than your number of hosts 16
```

## Built With

* Perl
* OpenSCAP - assessment tool
* CIS-CAT - assessment tool
* SCAP Security Guide - XML feeds for baseline assessments

## Authors

* **Jordan Alexis Caraballo-Vega** - University of Puerto Rico at Humacao
* Graham Mosley - University of Pennsylvania

## References

- SCAP
	National Institute of Standards and Technology (2009). The Security Content
	Automation Protocol (SCAP). Retrieved on June, 2016 from https://scap.nist.gov
- NVD Database
	National Vulnerability Database. Retrieved on June, 2016 from https://nvd.nist.gov/
- OVAL
	Open Vulnerability and Assessment Language. Retrieved on June, 2016 from
	http://oval.mitre.org/
- OpenSCAP
	OpenSCAP. Retreived on June, 2016 from https://www.open-scap.org/
- CIS-CAT
	Center for Internet Security. Retrieved on June, 2016 from
	https://benchmarks.cisecurity.org/

## Acknowledgments

  * George Rumney
  * John E. Jasen
  * Bennett Samowich
  * Maximiliano Guillen
  * Zed Pobre
