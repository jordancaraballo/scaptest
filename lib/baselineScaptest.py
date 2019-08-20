#************************************************************************************#
#!/usr/bin/python
# Automated SCAP Security Tool - Baseline and Compliance Test
# June 6, 2016 - August 12, 2016
# Author: Jordan Alexis Caraballo-Vega - University of Puerto Rico at Humacao
# Co-Author: Graham Mosley - University of Pennsylvania
# Mentors: George Rumney, John Jasen
#------------------------------------------------------------------------------------
#  Imports
#------------------------------------------------------------------------------------
import sys, os

#------------------------------------------------------------------------------------
#  Functions
#------------------------------------------------------------------------------------
def sanityChecks():
    if not os.geteuid() == 0:
        sys.exit("\nOnly root can run this script.\n")

def parseConfigFile():
    # parse configuration file here.
    return True

#------------------------------------------------------------------------------------
#  Main
#------------------------------------------------------------------------------------

