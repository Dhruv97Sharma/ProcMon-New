import os, psutil
import argparse, json
import hashlib, requests
import sqlite3
import io
import mpu
def main():
    parser = argparse.ArgumentParser(
        prog='python proc_mon.py ',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=('''\
                             Remote Monitoring Application 
                        ---------------------------------------
                        Suggestion : Use [-v|-q] to get Verbose
                                     and Quiet Output.
                                     
                                     
            '''))
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-v", "--verbose", help="Enable Verbose mode", action="store_true")
    group.add_argument("-q", "--quiet", help="Enable Quiet mode", action="store_true")

    args = parser.parse_args()
    verb, qui = args.verbose, args.quiet
    info = {}
    path = {}
    print ("Starting the Application!")
    try :
      if qui :
        for p in psutil.process_iter(attrs=['pid', 'name', 'connections', 'exe']):
             info[p.pid] = p.info
             path[p.pid] = p.info['exe']
      elif verb :
        for p in psutil.process_iter(attrs=['pid', 'name', 'connections', 'status', 'ppid', 'threads', 'exe']):
            info[p.pid] = p.info
            path[p.pid] = p.info['exe']
      else :
        for p in psutil.process_iter(attrs=['pid', 'name', 'connections', 'status', 'exe']):
            info[p.pid] = p.info
            path[p.pid] = p.info['exe']
    except(psutil.ZombieProcess, psutil.AccessDenied, psutil.NoSuchProcess):
        print ("Something unexpected happened!")


    dump_to_json(info, path)


def dump_to_json(info, path):
    print("Data is being dumped into json")

    proces = json.dumps(info, indent=4)

    mpu.io.write('data.json', proces)
    print(proces)
    dep = []
    for sync in path.keys():
        if path[sync] == None :
            pass
        else :
            dep.append(path[sync])
    print (str(dep))
    find_the_hash(dep)



def find_the_hash(dep):
    print ("FINDING hash for all the service path!!")
    BUF_SIZE=65536
    hash = {}
    for filename in dep:
        if filename in hash.keys():
            pass
        else :
            md5 = hashlib.md5()
            sha1 = hashlib.sha1()
            print(filename)
            fol = filename.encode("unicode_escape")
            try:
                with open(fol, 'rb') as f:
                    while True:
                        data = f.read(BUF_SIZE)
                        if not data:
                            break
                        md5.update(data)
                        sha1.update(data)
                    hash[fol] = md5.hexdigest()
                    print((md5.hexdigest()))
                    print((sha1.hexdigest()))

            except:
                pass
    print (hash)
    hash_only = hash.values()
    print (hash_only)
    virustotal_submit(hash_only)

#fo = open('jsondata',"w+")
#


def virustotal_submit(hash_only):
    print ("Submitting the HASH to Virustotal!")
    apikeys = ["f433eab5a81ac225ba4df785e889edc39cebb1210d7073c9cea12f2e2e6157d3",
              "b8acfc47cf0cd9d6bb515722f5c4dad6739f4e1a9669241e39d56d46e2675abb"]
    for api in apikeys:
        for hash_dep in hash_only:
          try:
            params = {
            'apikey': api,
            'resource': hash_dep
            }
            response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
            json_response = response.json()
            if type(json_response) is str:
                print(json.dumps(json.loads(json_response), sort_keys=True, indent=4))
            else:
                print(json.dumps(json_response, sort_keys=True, indent=4))
          except:
              break


#def get_result():

#def store_it():

if __name__ == "__main__":
    main()