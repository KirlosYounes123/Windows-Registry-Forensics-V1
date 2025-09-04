import re
from Registry.Registry import Registry,RegistryKeyNotFoundException
import argparse
import pathlib
import sys
from freq import *
import subprocess
import json
import os

def output_directory(DirectoryPath):
    path = pathlib.Path(DirectoryPath) / "alarms.json"
    path.touch(exist_ok=True)
    return path

def output_signs(DirectoryPath):
    path = pathlib.Path(DirectoryPath) / "signs.json"
    path.touch(exist_ok=True)
    return path

def init_json(AlarmsPath):
    with open(AlarmsPath,"w") as f:
        json.dump({},f,indent=4)

def alarms_for_runonce_random(Name,Value,Path,Context,Code,AlarmsPath):
    section = "Run Upon Startup"
    path = open(AlarmsPath,"r+")
    currentdata = json.load(path)
    if section not in currentdata:
        currentdata[section] = []
    data = {
        "Name":Name,
        "Value":Value,
        "Path":Path,
        "Code":Code,
        "Context":Context
    }
    currentdata[section].append(data)
    path.seek(0)
    json.dump(currentdata,path,indent=4)
    path.truncate()
    path.close()
    return

def alarms_for_runonce_vt(Name,Value,Path,Hash,Context,AlarmsPath):
    section = "Run Upon Startup"
    path = open(AlarmsPath,"r+")
    currentdata = json.load(path)
    if section not in currentdata:
        currentdata[section] = []
    data = {
        "Name":Name,
        "Value":Value,
        "Path":Path,
        "Code":"RUN02",
        "Hash":Hash,
        "Context":Context
    }
    currentdata[section].append(data)
    path.seek(0)
    json.dump(currentdata,path,indent=4)
    path.truncate()
    path.close()
    return

def virus_total_check_for_hash(Name,Value,Path,AlarmsPath,API):
        hash = subprocess.run(
            ["powershell", "-Command", rf"Get-FileHash -Path '{Path}' | ConvertTo-Json"],
            capture_output=True,
            text=True
        )
        if not hash.stdout:
            print(f"[!] Failed to get hash for {Path}")
            return None
        hash = json.loads(hash.stdout)
        result = subprocess.run([
                    "curl.exe",
                    "--request",
                    "GET",
                    "--url", f"https://www.virustotal.com/api/v3/files/{hash['Hash']}",
                    "--header",
                    f"x-apikey: {API}"
                ],capture_output=True,text=True)
        data = json.loads(result.stdout)
        last_analysis_stats = data["data"]["attributes"]["last_analysis_stats"]
        if last_analysis_stats["malicious"] > 0:
            Context = f"Virus Total {last_analysis_stats} Indicates That This File May Be Malicious."
            alarms_for_runonce_vt(Name,Value,Path,hash['Hash'],Context,AlarmsPath)
            return
        clean_keywords_result = ["None","null","clean"]
        clean_keywords_catagory = ["undetected","harmless"]
        last_analysis_results = data["data"]["attributes"]["last_analysis_results"]
        Counter = 0
        for engine, details in last_analysis_results.items():
            if str(details["result"]) in clean_keywords_catagory:
                continue
            elif str(details["category"]) in clean_keywords_catagory:
                continue
            else:
                Counter +=1
        if Counter >0:
            Context = f"One Or More Virus Total Engines Flagged The File Hash As Malicious."
            alarms_for_runonce_vt(Name,Value,Path,hash['Hash'],Context,AlarmsPath)
            return

def auto_run_check(registry_handler,apikey,AlarmsPath):
    paths = [r"Software\Microsoft\Windows\CurrentVersion\Run",r"Software\Microsoft\Windows\CurrentVersion\RunOnce",r"Microsoft\Windows\CurrentVersion\Run",r"Microsoft\Windows\CurrentVersion\RunOnce"]  

    def running_from_temp_path(Name,Value,Path,AlarmsPath):
        KnownTempPaths = [r"local\temp",r"windows\temp"]
        Path = Path.lower()
        temp = []
        for eachpath in KnownTempPaths:
            matches = re.findall(re.escape(eachpath),Path)
            if matches:
                temp.append(matches[0])
        if temp:
            Context = f"The {Name} App Is Running From A Temporary Directory Could Be Malicious."
            alarms_for_runonce_random(Name,Value,Path,Context,"RUN03",AlarmsPath)
    def frequncy_check(name,path,value,AlarmsPath):
        fc = FreqCounter()
        fc.load("freqtable2018.freq")
        if fc.probability(name)[0] < 30 and fc.probability(name)[1] < 30:
            Context = f"Application Name:{name} Is Probably A Malicious EXE Due To Randominess In Naming.The Program Is From The Path:*** {path} ***"
            alarms_for_runonce_random(name,value,path,Context,"RUN01",AlarmsPath)
        return
        
    for eachpath in paths:
        try:
            apps = registry_handler.open(eachpath)
        except RegistryKeyNotFoundException:
            print(f"Path: {eachpath} Was Not Found Trying Next Path.")
            continue
        values = apps.values()
        for eachvalue in values:
            name = eachvalue.name()
            value = eachvalue.value()
            path = re.findall(r"(.+?\.exe)\b",value)
            frequncy_check(name,path[0],value,AlarmsPath)
            virus_total_check_for_hash(name,value,path[0],AlarmsPath,apikey)
            running_from_temp_path(name,value,path[0],AlarmsPath)

def writing_sign_and_hashes(data,Signs):
    section = "Services"
    path = open(Signs,"r+")
    currentdata = json.load(path)
    if section not in currentdata:
        currentdata[section] = []
    currentdata[section].append(data)
    path.seek(0)
    json.dump(currentdata,path,indent=4)
    path.truncate()
    path.close()
    return

def alarms_for_non_valid_services(Name,result,Code,AlarmsPath):
    section = "Not Valid Service"
    path = open(AlarmsPath,"r+")
    currentdata = json.load(path)
    if section not in currentdata:
        currentdata[section] = []
    Context = "After Checking For The Sign Of The Service It Turns Out It Was Not Valid."
    data = {
        "Name":Name,
        "Results":result,
        "Code":Code,
        "Context":Context
    }
    currentdata[section].append(data)
    path.seek(0)
    json.dump(currentdata,path,indent=4)
    path.truncate()
    path.close()
    return

def alarms_for_non_valid_services_paths(Name,result,Code,AlarmsPath):
    section = "Not Valid Service"
    path = open(AlarmsPath,"r+")
    currentdata = json.load(path)
    if section not in currentdata:
        currentdata[section] = []
    Context = "After Checking For The Path Of The Service It Turned Out It Was Running From A Non Standard Path."
    data = {
        "Name":Name,
        "Results":result,
        "Code":Code,
        "Context":Context
    }
    currentdata[section].append(data)
    path.seek(0)
    json.dump(currentdata,path,indent=4)
    path.truncate()
    path.close()
    return

def service_check(registry_handler,apikey,AlarmsPath,Signs=None):
    def checking_for_sign(Name,ImagePath,AlarmsPath,Signs=None):
        sign = subprocess.run(
            ["powershell", "-Command", rf"Get-AuthenticodeSignature '{ImagePath}' | ConvertTo-Json"],
            capture_output=True,
            text=True,
            encoding="utf-8",  # add this
            errors="replace"   # optional: replaces undecodable chars with �
        )
        if not sign.stdout:
            print(f"[!] PowerShell returned nothing for {ImagePath}")
            return None
        if sign.returncode != 0:
            print(f"[!] PowerShell error")
            return None
        try:
            data = json.loads(sign.stdout)
        except json.JSONDecodeError:
            print(f"[!] Failed to parse JSON for {ImagePath}")
            return None
        result = {
        "Path": data.get("Path"),
        "StatusMessage": data.get("StatusMessage"),
        "Publisher": data.get("SignerCertificate", {}).get("Subject"),
        "Thumbprint": data.get("SignerCertificate", {}).get("Thumbprint"),
        "Status" : data.get("Status")
        }
        if Signs:
            writing_sign_and_hashes(result,Signs)
            return result
        if result["Status"] != 0:
            alarms_for_non_valid_services(Name,result,"S01",AlarmsPath)
            return result
        
    path = r"CurrentControlSet\Services" 
    listofsubkeys = registry_handler.root().subkeys()
    listofsubkeys = [x.name() for x in listofsubkeys]
    for eachkey in listofsubkeys:
        if "ControlSet" in eachkey:
            path = rf"{eachkey}\Services"
    try:
        services = registry_handler.open(path)
    except RegistryKeyNotFoundException:
        print(f"Path: {path} Was Not Found Trying Next Path.")
        return
    servicessub = services.subkeys()
    valuedict = defaultdict(lambda : [])
    valuesofsubkeys = []
    for eachservice in servicessub:
        for val in eachservice.values():
            valuedict[eachservice.name()].append(val)
    def pulling_names_values(data):
        return {data.name():data.value()}
    for eachvalue in valuedict.keys():
        listforvalues = valuedict[eachvalue]
        listforvalues = list(map(pulling_names_values,listforvalues))
        valuedict[eachvalue] = listforvalues
    Allowed_Paths = [r"C:\WINDOWS\System32",
                     r"C:\WINDOWS\SysWOW64",
                     r"C:\WINDOWS\System32\drivers",
                     r"C:\Program Files",
                     r"C:\Program Files (x86)",
                     r"C:\WINDOWS\WinSxS"]
    print("************************Beginning Validation Check For Services**************************")
    for eachimagepath in valuedict.keys():
        for eachdict in valuedict[eachimagepath]:
            ImagePath = eachdict.get("ImagePath")
            if ImagePath:
                path = re.search(r"(.+?\.(?:exe|dll|sys))\b", ImagePath, re.IGNORECASE)
                if path:
                    path = path.group(1)
                    if path.startswith("\\SystemRoot"):
                        windir = os.environ.get("SystemRoot", r"C:\Windows")
                        path = path.replace("\\SystemRoot", windir)
                    elif path.startswith("System32\\") or path.startswith("system32\\"):
                        path = os.path.join(windir, path)
                    resolved = os.path.expandvars(path) 
                    if "\\??\\C:" in resolved:
                        resolved = resolved[4:]
                    if re.findall(r'^"',resolved):
                        resolved = resolved[1:]
                    print(resolved)
                    Counter = 0 
                    for eachpath in Allowed_Paths:
                        if any(resolved.lower().startswith(eachpath.lower()) for eachpath in Allowed_Paths):
                            continue
                        else:
                            print("Service Is Running From A Non Standard Path Triggiring Alarm...")
                            result = checking_for_sign(eachimagepath, resolved, AlarmsPath, Signs)
                            if result:
                                alarms_for_non_valid_services_paths(eachimagepath, result, "S02", AlarmsPath)
                                break
                            else:
                                alarms_for_non_valid_services_paths(eachimagepath, resolved, "S02", AlarmsPath)
                                break
                    if Signs:
                        checking_for_sign(eachimagepath,resolved,AlarmsPath,Signs)
                        break
                    else:
                        checking_for_sign(eachimagepath,resolved,AlarmsPath)
            else:
                continue
def alarms_for_winlogon(Name,default,Code,keyvalue,AlarmsPath,Context):
    section = "Winlogon"
    path = open(AlarmsPath,"r+")
    currentdata = json.load(path)
    if section not in currentdata:
        currentdata[section] = []
    data = {
        "Name":Name,
        "DefaultValue":default,
        "CurrentValue":keyvalue,
        "Code":Code,
        "Context":Context
    }
    currentdata[section].append(data)
    path.seek(0)
    json.dump(currentdata,path,indent=4)
    path.truncate()
    path.close()
    return


def Winlogon(registry_handler,apikey,AlarmsPath):
    path = r"Microsoft\Windows NT\CurrentVersion\Winlogon"
    try:
        services = registry_handler.open(path)
    except RegistryKeyNotFoundException:
        print(f"Path: {path} Was Not Found Trying Next Path.")
        return
    def Shell(keyvalue):
        value = keyvalue.value()
        if "explorer.exe" not in value or not (re.fullmatch(r"explorer\.exe", value, re.IGNORECASE)):
            print("************ Suspicious Values Were Entered In Shell Key Check Alarms ****************")
            Context = "After Checking For The Value Of The Shell Key It Turns Out The Default Value Was Modified."
            alarms_for_winlogon(keyvalue.name(),"explorer.exe","WINLOGON01",value,AlarmsPath,Context)
            return
        return
    
    def Userinit(keyvalue):
        pattern = r"C:\\Windows\\System32\\userinit\.exe,"
        if not (re.fullmatch(pattern,keyvalue.value(), re.IGNORECASE)):
            print("************ Suspicious Values Were Entered In Userinit Key Check Alarms ****************")
            Context = "After Checking For The Value Of The Userinit Key It Turns Out The Default Value Was Modified."
            alarms_for_winlogon(keyvalue.name(),pattern,"WINLOGON02",keyvalue.value(),AlarmsPath,Context)
            return
        return
    
    def AutoAdminLogon(keyvalue):
        if keyvalue.value() != 0 :
            print("************ Default Value For AutoAdminLogon Key Was Changed From Default Check Alarms ****************")
            Context = "After Checking For The Value Of The AutoAdminLogon Key It Turns Out The Default Value Was Modified."
            alarms_for_winlogon(keyvalue.name(),"0","WINLOGON03",keyvalue.value(),AlarmsPath,Context)
            return
        return
    
    def DefaultName(keyvalue,name):
        if keyvalue.value() != None :
            print(f"************ Default Value For {name} Key Was Changed From Default Check Alarms ****************")
            Context = "After Checking For The Value Of The {name} Key It Turns Out The Default Value Was Modified."
            alarms_for_winlogon(keyvalue.name(),"Empty","WINLOGON04",keyvalue.value(),AlarmsPath,Context)
            return
        return
    
    def VMApplet(keyvalue):
        if keyvalue.value() != "SystemPropertiesPerformance.exe /pagefile":
            print("************ Default Value For VMApplet Key Was Changed From Default Check Alarms ****************")
            Context = "After Checking For The Value Of The VMApplet Key It Turns Out The Default Value Was Modified."
            alarms_for_winlogon(keyvalue.name(),"SystemPropertiesPerformance.exe /pagefile","WINLOGON05",keyvalue.value(),AlarmsPath,Context)
            return
        return

    def UIHost(keyvalue):
        if keyvalue.value() != "logonui.exe":
            print("************ Default Value For UIHost Key Was Changed From Default Check Alarms ****************")
            Context = "After Checking For The Value Of The UIHost Key It Turns Out The Default Value Was Modified."
            alarms_for_winlogon(keyvalue.name(),"logonui.exe","WINLOGON06",keyvalue.value(),AlarmsPath,Context)
            return
        return

    def ShellAppRuntime(keyvalue):
        if keyvalue.value() != "ShellAppRuntime.exe":
            print("************ Default Value For ShellAppRuntime Key Was Changed From Default Check Alarms ****************")
            Context = "After Checking For The Value Of The ShellAppRuntime Key It Turns Out The Default Value Was Modified."
            alarms_for_winlogon(keyvalue.name(),"ShellAppRuntime.exe","WINLOGON07",keyvalue.value(),AlarmsPath,Context)
            return
        return

    def ShellInfrastructure(keyvalue):
        if keyvalue.value() != "sihost.exe":
            print("************ Default Value For ShellInfrastructure Key Was Changed From Default Check Alarms ****************")
            Context = "After Checking For The Value Of The ShellInfrastructure Key It Turns Out The Default Value Was Modified."
            alarms_for_winlogon(keyvalue.name(),"sihost.exe","WINLOGON07",keyvalue.value(),AlarmsPath,Context)
            return
        return

    print("******** Cheking For Winlogon Keys And Values ********")
    keys = ["Shell","Userinit",
            "AutoAdminLogon","DefaultUserName",
            "DefaultDomainName","DefaultPassword",
            "LegalNoticeCaption","LegalNoticeText",
            "VMApplet","UIHost","ShellAppRuntime","ShellInfrastructure",
            "ReportBootOk","ShutdownFlags","GpExtensions"]
    keystocheck = []
    winlogon = registry_handler.open(path)
    def values_of_winlogon(x):
        return x.name()
    NamesOfValues = list(map(values_of_winlogon,winlogon.values()))
    for eachname in NamesOfValues:
        if eachname in keys:
            keystocheck.append(eachname)
    for eachvalue in winlogon.values():
        if eachvalue.name() == "Shell":
            print(f"Checking For {eachvalue.name()} Key ....")
            Shell(eachvalue)
        elif eachvalue.name() == "Userinit":
            print(f"Checking For {eachvalue.name()} Key ....")
            Userinit(eachvalue)
        elif eachvalue.name() == "AutoAdminLogon":
            print(f"Checking For {eachvalue.name()} Key ....")
            AutoAdminLogon(eachvalue)
        elif eachvalue.name() in ["DefaultUserName","DefaultDomainName","DefaultPassword"]:
            print(f"Checking For {eachvalue.name()} Key ....")
            DefaultName(eachvalue,eachvalue.name())
        elif eachvalue.name() == "VMApplet":
            print(f"Checking For {eachvalue.name()} Key ....")
            VMApplet(eachvalue)
        elif eachvalue.name() == "UIHost":
            print(f"Checking For {eachvalue.name()} Key ....")
            UIHost(eachvalue)
        elif eachvalue.name() == "ShellAppRuntime":
            print(f"Checking For {eachvalue.name()} Key ....")
            UIHost(eachvalue)
        else:
            continue

def alarms_for_appinit(Name,default,Code,keyvalue,AlarmsPath,Context):
    section = "AppInit"
    path = open(AlarmsPath,"r+")
    currentdata = json.load(path)
    if section not in currentdata:
        currentdata[section] = []
    data = {
        "Name":Name,
        "DefaultValue":default,
        "CurrentValue":keyvalue,
        "Code":Code,
        "Context":Context
    }
    currentdata[section].append(data)
    path.seek(0)
    json.dump(currentdata,path,indent=4)
    path.truncate()
    path.close()
    return

def AppInit(registry_handler,apikey,AlarmsPath):
    path = r"Microsoft\Windows NT\CurrentVersion\Windows"
    try:
        services = registry_handler.open(path)
    except RegistryKeyNotFoundException:
        print(f"Path: {path} Was Not Found Trying Next Path.")
        return
    def AppInit_Dll(keyvalue):
        if keyvalue.value() != "":
            print("************ Default Value For AppInit_Dlls Key Was Changed From Default Check Alarms ****************")
            Context = "After Checking For The Value Of The AppInit_Dll Key It Turns Out The Default Value Was Modified."
            alarms_for_appinit(keyvalue.name(),"Empty","APPINIT01",keyvalue.value(),AlarmsPath,Context)
            return
        return
    
    def LoadAppInit_DLLs(keyvalue):
        if keyvalue.value() != 0:
            print("************ Default Value For LoadAppInit_DLLs Key Was Changed From Default Check Alarms ****************")
            Context = "After Checking For The Value Of The LoadAppInit_DLLs Key It Turns Out The Default Value Was Modified."
            alarms_for_appinit(keyvalue.name(),"0","APPINIT02",keyvalue.value(),AlarmsPath,Context)
            return
        return
    print("************************Beginning Validation Check For APPINIT**************************")
    AppInitValues = services
    for eachvalue in AppInitValues.values():
        if eachvalue.name() == "AppInit_DLLs":
            print(f"Checking For {eachvalue.name()} Key ....")
            AppInit_Dll(eachvalue)
        elif eachvalue.name() == "LoadAppInit_DLLs":
            print(f"Checking For {eachvalue.name()} Key ....")
            LoadAppInit_DLLs(eachvalue)
        else:
            continue

def alarms_for_taskmgr(Name,default,Code,keyvalue,AlarmsPath,Context):
    section = "TSK | REG"
    path = open(AlarmsPath,"r+")
    currentdata = json.load(path)
    if section not in currentdata:
        currentdata[section] = []
    data = {
        "Name":Name,
        "DefaultValue":default,
        "CurrentValue":keyvalue,
        "Code":Code,
        "Context":Context
    }
    currentdata[section].append(data)
    path.seek(0)
    json.dump(currentdata,path,indent=4)
    path.truncate()
    path.close()
    return

def TaskManger(registry_handler,apikey,AlarmsPath):
    path = r"Software\Microsoft\Windows\CurrentVersion\Policies\System"
    try:
        taskmanger = registry_handler.open(path)
    except RegistryKeyNotFoundException:
        print(f"Path: {path} Was Not Found Trying Next Path.")
        return
    print("************************Beginning Validation Check For TaskManager**************************")
    def TaskMgrCheck(keyvalue):
        if keyvalue.value() != 0:
            print("************ Task Manger Was Disabled ****************")
            Context = "It Looks Like Task Manger Was Disabled (This Could Be A Policy Better Check). "
            alarms_for_taskmgr(keyvalue.name(),"0","TSMG01",keyvalue.value(),AlarmsPath,Context)
            return
        return
    for eachvalue in taskmanger.values():
        if eachvalue.name() == "DisableTaskMgr":
            print("Checking If Task Manger is Disabled For This User....")
            TaskMgrCheck(eachvalue)

def RegTools(registry_handler,apikey,AlarmsPath):
    path = r"Software\Microsoft\Windows\CurrentVersion\Policies\System"
    try:
        regtools = registry_handler.open(path)
    except RegistryKeyNotFoundException:
        print(f"Path: {path} Was Not Found Trying Next Path.")
        return
    def regtoolscheck(keyvalue):
        if keyvalue.value() != 0:
            print("************ Registry Tools Were Disabled ****************")
            Context = "It Looks Like Registry Tools Was Disabled (This Could Be A Policy Better Check). "
            alarms_for_taskmgr(keyvalue.name(),"0","REGT01",keyvalue.value(),AlarmsPath,Context)
            return
    print("************************Beginning Validation Check For Registry Tools**************************")
    for eachvalue in regtools.values():
        if eachvalue.name() == "DisableRegistryTools":
            print("Checking If Registry Tools is Disabled For This User....")
            regtoolscheck(eachvalue)

def alarms_for_UAC(Name,default,Code,keyvalue,AlarmsPath,Context):
    section = "UAC"
    path = open(AlarmsPath,"r+")
    currentdata = json.load(path)
    if section not in currentdata:
        currentdata[section] = []
    data = {
        "Name":Name,
        "DefaultValue":default,
        "CurrentValue":keyvalue,
        "Code":Code,
        "Context":Context
    }
    currentdata[section].append(data)
    path.seek(0)
    json.dump(currentdata,path,indent=4)
    path.truncate()
    path.close()
    return

def UAC(registry_handler,apikey,AlarmsPath):
    path = r"Microsoft\Windows\CurrentVersion\Policies\System"
    try:
        uac = registry_handler.open(path)
    except RegistryKeyNotFoundException:
        print(f"Path: {path} Was Not Found Trying Next Path.")
        return
    
    def EnableUA(keyvalue):
        if keyvalue.value() != 1:
            print("*********** EnableUA Was Disabled *************")
            Context = "It Looks Like Something Or Someone Is Trying To Run Unprivilaged Activity By Disabling EnablaUA Key."
            alarms_for_UAC(keyvalue.name(),"1","UAC01",keyvalue.value(),AlarmsPath,Context)

    def Concent(keyvalue):
        if keyvalue.value() != 2:
            print("*********** ConsentPromptBehaviorAdmin Was Disabled *************")
            Context = "It Looks Like Something Or Someone Is Trying To Run Unprivilaged Activity By Disabling EnablaUA Key."
            alarms_for_UAC(keyvalue.name(),"2","UAC02",keyvalue.value(),AlarmsPath,Context)
    print("************************Beginning Validation Check For UAC**************************")
    for eachvalue in uac.values():
        if eachvalue.name() == "EnableLUA":
            print("Checking if EnableUA Was Disabled ...")
            EnableUA(eachvalue)
        elif eachvalue.name() == "ConsentPromptBehaviorAdmin":
            print("Checking For Concent On Secure Desktop....")

def alarms_for_WD(Name,Code,keyvalue,AlarmsPath,Context):
    section = "Windows Defender"
    path = open(AlarmsPath,"r+")
    currentdata = json.load(path)
    if section not in currentdata:
        currentdata[section] = []
    data = {
        "Name":Name,
        "Value":keyvalue,
        "Code":Code,
        "Context":Context
    }
    currentdata[section].append(data)
    path.seek(0)
    json.dump(currentdata,path,indent=4)
    path.truncate()
    path.close()
    return


def WindowsDefender(registry_handler,apikey,AlarmsPath):
    path = r"Policies\Microsoft\Windows Defender"
    try:
        wd = registry_handler.open(path)
    except RegistryKeyNotFoundException:
        print(f"Path: {path} Was Not Found Trying Next Path.")
        return
    print("************************Beginning Validation Check For Windows Defender**************************")
    if wd.values():
        print("********** Windows Defender Keys Were Added (Possible Malicious Activity) ***********")
        Context = "It Appears That Some Keys Have Been Added To Windows Defender Registry Managment Keys"
        for eachvalue in wd.values():
            alarms_for_WD(eachvalue.name(),"WD01",eachvalue.value(),AlarmsPath,Context)


def alarms_for_firewall(Name,default,Code,keyvalue,AlarmsPath,Context):
    section = "Firewall"
    path = open(AlarmsPath,"r+")
    currentdata = json.load(path)
    if section not in currentdata:
        currentdata[section] = []
    data = {
        "Name":Name,
        "DefaultValue":default,
        "CurrentValue":keyvalue,
        "Code":Code,
        "Context":Context
    }
    currentdata[section].append(data)
    path.seek(0)
    json.dump(currentdata,path,indent=4)
    path.truncate()
    path.close()
    return

def Firewall(registry_handler,apikey,AlarmsPath):
    path = r"CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy" 
    listofsubkeys = registry_handler.root().subkeys()
    listofsubkeys = [x.name() for x in listofsubkeys]
    for eachkey in listofsubkeys:
        if "ControlSet" in eachkey:
            path = rf"{eachkey}\Services\SharedAccess\Parameters\FirewallPolicy"
    try:
        fw = registry_handler.open(path)
    except RegistryKeyNotFoundException:
        print(f"Path: {path} Was Not Found Trying Next Path.")
        return
    def alarming(eachvalue,name):
        print(f"********* {name} Was Disabled On Domain Profile *********")
        Context = "{name} was disabled by some activity in this windows machine this needs to be invistigated."
        alarms_for_firewall(eachvalue.name(),"1","FW01",eachvalue.value(),AlarmsPath,Context)
    print("************************Beginning Validation Check For Host Firewall**************************")
    for eachsubkey in fw.subkeys():
        if eachsubkey.name() == "DomainProfile":
            DomainProfile = eachsubkey
        elif eachsubkey.name() == "StandardProfile":
            StandardProfile = eachsubkey
        else:
            continue
    for eachvalue in DomainProfile.values():
        if eachvalue.name() == "EnableFirewall":
            if eachvalue.value() != 1:
                alarming(eachvalue,"Firewall")
        elif eachvalue.name() == "DisableNotifications":
            if eachvalue.value() != 0 :
                alarming(eachvalue,"Firewall Notifications")
    for eachvalue in StandardProfile.values():
        if eachvalue.name() == "EnableFirewall":
            if eachvalue.value() != 1:
                alarming(eachvalue,"Firewall")
        elif eachvalue.name() == "DisableNotifications":
            if eachvalue.value() != 0 :
                alarming(eachvalue,"Firewall Notifications")

    
def API_Extraction(FilePath):
    path = pathlib.Path(FilePath)
    data = path.read_text().strip()
    return data


DEFAULT_OUTPUT_DIR = pathlib.Path.cwd() / "Output"
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-r','--registry',type=pathlib.Path,required=True,help='Path To The Registry File To Parse.')
    parser.add_argument('-A','--api',type=pathlib.Path,required=True,help='Path To The API Text File. (Just Create A Text File And Put Inside Of It The API Key.)')
    parser.add_argument('-D','--directory',type=pathlib.Path,required=False,help="Path For Directory For Saving Output Files.")
    parser.add_argument('-S','--signs',type=pathlib.Path,required=False,help="Path For Directory For Saving Information About Signed And Unsigned Services.")
    args = parser.parse_args()

    if not pathlib.Path(args.registry).exists():
        print("Registry File Does Not Exist.")
        sys.exit(1)
    if not pathlib.Path(args.api).exists():
        print("API File Does Not Exist.")
        sys.exit(2)

    if args.directory:    
        if not pathlib.Path(args.directory).exists():
            if pathlib.Path(args.directory).parent.exists():
                output_dir = pathlib.Path(args.directory)
                output_dir.mkdir()
                args.directory = output_dir
                print(f"Output Will Be Stored In:{pathlib.Path(args.directory)}")
            else:
                print("Given Directory Path Or Parent Path Doesn't Exist, Creating Output Direcory In Current Working Directory...")
                output_dir = DEFAULT_OUTPUT_DIR
                output_dir.mkdir(parents=True,exist_ok=True)
                args.directory = output_dir
    else:
        print("Was Not Given A Path For Output Directory, Creating Output Direcory In Current Working Directory...")
        output_dir = DEFAULT_OUTPUT_DIR
        output_dir.mkdir(parents=True,exist_ok=True)
        args.directory = output_dir
    AlarmsPath = output_directory(args.directory)
    init_json(AlarmsPath)
    registry_handler = Registry(args.registry)
    apikey = API_Extraction(args.api)
    auto_run_check(registry_handler,apikey,AlarmsPath)
    if args.signs:
        signs = output_signs(args.signs)
        init_json(signs)
        service_check(registry_handler,apikey,AlarmsPath,signs)
    else:
        service_check(registry_handler,apikey,AlarmsPath)
    Winlogon(registry_handler,apikey,AlarmsPath)
    AppInit(registry_handler,apikey,AlarmsPath)
    TaskManger(registry_handler,apikey,AlarmsPath)
    RegTools(registry_handler,apikey,AlarmsPath)
    UAC(registry_handler,apikey,AlarmsPath)
    WindowsDefender(registry_handler,apikey,AlarmsPath)
    Firewall(registry_handler,apikey,AlarmsPath)
if __name__ == "__main__":
    main()
