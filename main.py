import paramiko
import csv
#from parseYaml import checks, parsed_yaml_file
import re
import glob
import json
import argparse
import datetime
import requests


global outputDirectory
outputDirectory={}
global pass1
global scanStatus

def runAudit(num, command):
    print(command+"\n")
    input, output, e = ssh.exec_command(command,timeout=300)
    if command[0:7]=="sudo -S":
        input.write(pass1+ "\n")
        input.flush()
    #print(output)
    line=output.readlines()
    if len(line) == 0:
        line.insert(0,"")
    return line

parser = argparse.ArgumentParser()
#parser.add_argument("-clairIP", help="IP address of clair service you want to login via ssh connection")
parser.add_argument("-imageName", help="Name and tag of image you want to scan via ssh connection")
#parser.add_argument("-tag", help="Tag version of image you want to scan via ssh connection")
args = parser.parse_args()

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
#pass1 = getpass.getpass('Please input password to login via ssh connection: ')
pass1='pp1234'
imageName=args.imageName
#imageTag=args.tag

ssh.connect(hostname='192.168.30.123', username='k', password=pass1, allow_agent = 'true', timeout=10)
print('[*]Login successfully with SSH connection ')

f_exec_log = open('execlog.txt', 'a')
print('[*]logging start up!')

def main():
    scanStatus=0 #normal status
    #get hash ID
    SSHcommand="/root/clair-v4.4.4/cmd/clairctl/clairctl manifest "+imageName
    manifestOutput =runAudit(0,SSHcommand)
    try:
        manifestJson=json.loads(manifestOutput[0])
        imageHashID=manifestJson["hash"]
        print(imageHashID)
    except:
        print("Unknown image name or tag name\n")
        scanStatus=1 #normal status
    
    #image security analysis
    SSHcommand="/root/clair-v4.4.4/cmd/clairctl/clairctl report "+imageName
    scanOutput =runAudit(0,SSHcommand)

    if(scanStatus==0):
        f_exec_log.write("Scan start:"+imageName+","+imageHashID+","+str(datetime.datetime.now())+"\n")
    
        #print(scanOutput)
        #get json file of scan result
        scanResultUrl="http://192.168.30.123:6060/matcher/api/v1/vulnerability_report/"+imageHashID
        responseStatuses = {200: "Website Available",301: "Permanent Redirect",302: "Temporary Redirect",404: "Not Found",500: "Internal Server Error",503: "Service Unavailable"}
    
        try:
            web_response = requests.get(scanResultUrl,timeout=3)
            print(scanResultUrl, responseStatuses[web_response.status_code])
            print(web_response.text)
        except:
            print("Connection error\n")


if __name__ == "__main__":
    main()
