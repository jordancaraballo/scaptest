#!/usr/bin/python
"""
# -----------------------------------------------------------------------------------------
# The main purpose of this script is to parse files from Windows CIS-CAT assesments that come from
# different hosts and to summarize them in a single file. By running this script as a cron job,
# the admin will be able to have a single file with the summary of the different scores. This
# includes Compliance and Vulnerabilities tests. The output are two text files with the scores.
# Author: Jordan Alexis Caraballo-Vega
# -----------------------------------------------------------------------
"""
import glob
import os, sys
import os.path

# General Variables
FilesPath = "Path" # string of path that stores the reports, end with /
CompName  = FilesPath + "Win-CIS-CAT-ComplianceScores.txt"       # name of the compliance resulting file
VulnName  = FilesPath + "Win-CIS-CAT-VulnerabilitiesScores.txt"  # name of the vulnerable resulting file
NumHosts  = 12                                                   # int with the amount of hosts top assess

# Function to assess compliance files
# It takes a list of the files, the resulting filename, the path and the number of hosts.
# It creates a dictionary with the values and creates or appends results to the file.
def assessCompliance(filesList, compFileName, filesPath, numHosts):
    complianceScoresList = list()
    for file in filesList:
        tmpDict, host, date = createCompDict(file)
        complianceScoresList.append(tmpDict)
    createCompScoreFile(complianceScoresList, compFileName, host, date, numHosts)

# Funtion to parse a compliance file and return a dict with the results elements
# It creates the dictionary with the elements from the cvs files.
def createCompDict(compFile):
    compDict = dict() # dictionary to append the data
    with open(compFile) as compData: # open file and read lines
        lines = compData.readlines()
        item = lines[0].split(",")[-5:] + lines[1].split(",")[-6:]
        date, host = lines[0].split(",")[:2] # position where the date and hosts are located
        # Split resulting line and get scores
        for i in item:
            cleanString = i.split(": ")
            compDict[cleanString[0]] = cleanString[1].strip()
    return compDict, host, date

# Function to append scores to compliance text file
def createCompScoreFile(compList, compFile, host, date, numHosts):
    with open(compFile, 'a') as the_file:
        the_file.write('\nDate CIS-CAT Compliance Assessment - Last Updated On ' + date + '\n')
        for hostscore in compList:
            the_file.write('Host: ' + host + ', Score: ' + hostscore['Score'] + ' (' + hostscore['Pass'] + '/' + hostscore['Maximum Possible'])
            the_file.write('), Unknown: ' + hostscore['Unknown'] + ', Not selected: ' + hostscore['Not Selected'] + ', Error: ' + hostscore['Error']+'\n')
        if len(compList) < numHosts:
            the_file.write('WARN: The amount of scores ' + str(len(compList)) + ' is less than your number of hosts ' + str(numHosts) + ' \n')

# Function to assess compliance files
def assessVulnerabilities(filesList, vulnFileName, filesPath, numHosts):
    vulnerabilitiesScoresList = list()
    for file in filesList:
        vulnerabilitiesScoresList.append(createVulnDict(file))
    createVulnScoreFile(vulnerabilitiesScoresList, vulnFileName, numHosts)

# Funtion to parse a file and return a dict with the results elements
def createVulnDict(vulnFile):
    vulnDict = dict()
    with open(vulnFile) as vulnData:
        for x in xrange(8):
            item = vulnData.next().split(":\",")  # split string
            vulnDict[item[0][1:]] = item[1][1:-3] # index dict and clean values
    return vulnDict

# Function to append scores to vulnerabilities text file
def createVulnScoreFile(vulnList, vulnFile, numHosts):
    with open(vulnFile, 'a') as the_file:
        the_file.write('\nDate CIS-CAT Vulnerability Assessment - Last Updated On ' + vulnList[0]['Last Updated On'] + '\n')
        for vulnDict in vulnList:
            # Future: Overwrite string to maintain it alligned
            the_file.write('Host: ' + vulnDict['Target Name'] + ', OS: ' + vulnDict['Target OS'])
            the_file.write(', Score: ' + vulnDict['Total Found'] + ' Vulnerabilities ')
            the_file.write(vulnDict['Total High'] + '-High ' + vulnDict['Total Medium'] + '-Medium ' + vulnDict['Total Low'] + '-Low\n')
        if len(vulnList) < numHosts:
            the_file.write('WARN: The amount of scores ' + str(len(vulnList)) + ' is less than your number of hosts ' + str(numHosts) + ' \n')

# Function to send email. Still testing it.
def sendResults():
    import smtplib
    server = smtplib.SMTP('imap.gmail.com',587)
    server.login("sender_email", "passwd")
    msg = "Hola"
    server.sendmail("sender_email","receiver_email", msg)

### Create list with all the csv available files
ComplianceFilesList = glob.glob(FilesPath + "*-report-*.csv")
VulnerableFilesList = glob.glob(FilesPath + "*-Vulnerability-*.csv")

if len(ComplianceFilesList) == 0 or len(VulnerableFilesList) == 0:
   sys.exit("Error: Report files were not found.")

### Loop to assess the files
assessCompliance(ComplianceFilesList, CompName, FilesPath, NumHosts)
assessVulnerabilities(VulnerableFilesList, VulnName, FilesPath, NumHosts)

#sendResults()

### Verify if files exits
if os.path.isfile(CompName) and os.access(CompName, os.R_OK):
    print "Compliance Scoring Assessment Done. View results at " + CompName
else:
    sys.exit("Error: " + CompName + " not found. Either file is missing or is not readable")

if os.path.isfile(VulnName) and os.access(VulnName, os.R_OK):
    "Vulnerability Scoring Assessment Done. View results at " + VulnName
else:
    sys.exit("Error: " + VulnName + " not found. Either file is missing or is not readable")
