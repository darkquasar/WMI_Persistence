# WMI_Persistence
A repo to hold some scripts pertaining WMI (Windows implementation of WBEM) forensics

## Usage:
python WMIPers.py Name_of_File (Usually OBJECTS.DATA)

## Description:
This script is meant to find WMI persistence by directly parsing the contents of OBJECTS.DATA files. It doesn't require any particular dependencies other than standard Python libraries. 

## References: 
The script was inspire in the work of Graeber about WMI persistence mechanisms:
https://www.blackhat.com/docs/us-15/materials/us-15-Graeber-Abusing-Windows-Management-Instrumentation-WMI-To-Build-A-Persistent%20Asynchronous-And-Fileless-Backdoor-wp.pdf

## Future Improvements: 
1) Scan all hosts in your network via SMB using the script
2) Export results to CSV
3) Scan multiple WMI Databases inside a folder
4) Extract more forensically relevant info from OBJECTS.DATA

