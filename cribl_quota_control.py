#!/usr/bin/python

import requests
import json
import sys
import argparse
import getpass

# I don't care about insecure certs (maybe you do, comment out if so)
requests.urllib3.disable_warnings(requests.urllib3.exceptions.InsecureRequestWarning)

# we operate in gizzies
gb = 1_000_000_000

# where we login to get a bearer token
auth_uri = '/api/v1/auth/login'
cloud_token_url = 'https://login.cribl.cloud/oauth/token'

# define the var URI
# example PATCH payload: {"type":"boolean","value":"false","id":"testvar"}
var_update_uri  = '/api/v1/m/<WG>/lib/vars/'

# with everything in place, we need to commit and deploy using these URIs
# commit payload: {"message": "quota control change",  "group": "<WG>",  "files": ["groups/<WG>/local/cribl/vars.yml"]}
# deploy payload: {"version":"<commit-ID-from-previous>"}
commit_uri = '/api/v1/version/commit'
deploy_uri = '/api/v1/master/groups/<WG>/deploy'

# metrics query URI
metrics_query_uri = '/api/v1/system/metrics/query'
metrics_query_data = '{\
    "where":"output == \\"<OUTPUT_ID>\\"",\
    "aggs":{"aggregations":[\
        "sum(\\"total.out_events\\").as(\\"events\\")",\
        "sum(\\"total.out_bytes\\").as(\\"bytes\\")"\
    ],\
    "cumulative":true},\
    "earliest":"-0d@d"\
}'

#############################
# prompt for password if one is not supplied
class Password:
    # if password is provided, use it. otherwise prompt
    DEFAULT = 'Prompt if not specified'

    def __init__(self, value):
        if value == self.DEFAULT:
            value = getpass.getpass('Password: ')
        self.value = value

    def __str__(self):
        return self.value

#############################
# parse the command args
def parse_args():
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-D', '--debug', help='Extra output',action='store_true')
    parser.add_argument('-l', '--leader', help='Leader URL, http(s)://leader:port',required=True)
    parser.add_argument('-g', '--group', type=str, help="Target worker group", required=True)
    parser.add_argument('-n', '--varname', type=str, help="Global Variable name to update", required=True) 
    #parser.add_argument('-v', '--varvalue', type=str, help="Global Variable value", required=True) 
    parser.add_argument('-o', '--outputid', help='Output to check for quota',required=True)
    parser.add_argument('-q', '--quotagb', help='GB quota',required=True)
    parser.add_argument('-u', '--username', help='API token id (cloud) or user id (self-managed)',required=True)
    parser.add_argument('-P', '--password', type=Password, help='Specify password or secret, or get prompted for it',default=Password.DEFAULT)
    args = parser.parse_args()
    return args

# some debug notes
def debug_log(log_str):
    if args.debug:
        print("DEBUG: {}".format(log_str))

#############################
#############################
# commit the change
def commit(leader, group, headers):
    url = leader + commit_uri
    data = {"message": "quota control change",  "group": group,  "files": ["groups/<WG>/local/cribl/vars.yml".replace("<WG>",group)]}
    r = requests.post(url,headers=headers,json=data)
    debug_log("POST to: " + url)
    debug_log("with data: " + json.dumps(data))

    if (r.status_code == 200):
        return(r)
    else:
        print("PATCH commit failed with returned status {}\nexiting!".format(r.status_code))
        print("details:\nurl: {}\nheaders: {}\ndata: {}\n".format(url,headers,json.dumps(data)))
        sys.exit(1)

#############################
# deploy this specific commit
def deploy(leader, group, headers, commit_id):
    url = leader + deploy_uri.replace("<WG>",group)
    data = {'version': commit_id}
    r = requests.patch(url,headers=headers,data=json.dumps(data))
    debug_log("PATCH: " + url)
    debug_log("with data: " + json.dumps(data))
    
    if (r.status_code == 200):
        return(r)
    else:
        print("PATCH deploy failed with returned status {}\nexiting!".format(r.status_code))
        print("details:\nurl: {}\nheaders: {}\ndata: {}\n".format(url,headers,json.dumps(data)))
        sys.exit(1)

#############################
# get current value of the variable
def gv_get(leader,group,headers,varname):
    url = leader + var_update_uri.replace("<WG>",group) + varname
    debug_log("GET to {}".format(url))
    r = requests.get(url,headers=headers)
    # if query worked, return the response
    if (r.status_code == 200):
        debug_log("results: {}".format(r.json()))
        return(r)
    else:
        print("PATCH failed with returned status {}\nexiting!".format(r.status_code))
        sys.exit(1)

#############################
# update the variable
def gv_update(leader,group,headers, varname, varvalue):
    url = leader + var_update_uri.replace("<WG>",group) + varname
    data = {"type":"string","value":varvalue,"id":varname}
    debug_log("PATCH to {}".format(url))
    r = requests.patch(url,headers=headers, data=json.dumps(data))
    
    # if upload worked, return the response
    if (r.status_code == 200):
        debug_log("results: {}".format(r.json()))
        return(r)
    else:
        print("PATCH failed with returned status {}\nexiting!".format(r.status_code))
        sys.exit(1)

#############################
# check the output counter
def get_counter(leader,group,headers,output_id,earliest):
    url = leader + metrics_query_uri
    data = metrics_query_data.replace("<OUTPUT_ID>",output_id)
    #debug_log("POST to {}\n with data\n{}".format(url, data))
    r = requests.post(url,headers=headers, data=data)
    
    # if query worked, return the response
    if (r.status_code == 200):
        return(int(r.json()['results'][0]['bytes']))
    else:
        print("POST metrics query failed with returned status {}\nexiting!".format(r.status_code))
        sys.exit(1)


#############################
# only one of the auth functions will fire
# either self-managed or SaaS
#############################
# get logged in for self-managed instances
def auth(leader_url,un,pw):
    # get logged in and grab a token
    header = {'accept': 'application/json', 'Content-Type': 'application/json'}
    login = '{"username": "' + un + '", "password": "' + pw + '"}'
    r = requests.post(leader_url+auth_uri,headers=header,data=login,verify=False)
    if (r.status_code == 200):
        res = r.json()
        return res["token"]
    else:
        print("Login failed, terminating")
        print(str(r.json()))
        sys.exit()
#############################
# get logged in for Cribl SaaS
def cloud_auth(client_id,client_secret):
    # get logged in and grab a token
    header = {'accept': 'application/json', 'Content-Type': 'application/json'}
    login = '{"grant_type": "client_credentials","client_id": "' + client_id + '", "client_secret": "' + client_secret + '","audience":"https://api.cribl.cloud"}'
    r = requests.post(cloud_token_url,headers=header,data=login,verify=False)
    if (r.status_code == 200):
        res = r.json()
        #debug_log("Bearer token: " + res["access_token"])
        return res["access_token"]
    else:
        print("Login failed, terminating")
        print(str(r.json()))
        sys.exit()
#############################
#############################
# main 
if __name__ == "__main__":
    args = parse_args()
    
    # get logged in
    if args.leader.find('cribl.cloud') > 0:
        bearer_token = cloud_auth(args.username,str(args.password))
    else:
        bearer_token = auth(args.leader,args.username, str(args.password))
    
    # set-up default headers with bearer token, content-type and accept
    headers = {'Authorization': 'Bearer ' + bearer_token, 'accept': 'application/json', 'Content-Type': 'application/json'}
    
    # check the quota
    debug_log("checking quota")
    bytes = get_counter(args.leader,args.group,headers,args.outputid,"-0d@d")
    debug_log("current volume reading: " + str(bytes/gb) + " GB")
    overq = bytes/gb > int(args.quotagb)
    
    # check the current flag
    debug_log("checking current global variable")
    results = gv_get(args.leader,args.group,headers,args.varname)
    debug_log(results.status_code)
    flag = results.json()['items'][0]['value']
    debug_log("current flag: " + flag)

    # do we need to update? default no and relief valve closed
    update_flag = False
    target_value = "false"
    
    # if the current flag is false and we're over quota, we need to update
    if overq and flag == "false":
        target_value = "true"
        update_flag = True
    elif not overq and flag == "true":
        target_value = "false"
        update_flag = True
    debug_log("do we need update? " + str(update_flag))
    
    # Update the var if we're over quota and flag is false
    if update_flag:
        debug_log("updating GV " + args.varname + " to " + target_value)
        results = gv_update(args.leader,args.group,headers,args.varname,target_value)
        debug_log(results.status_code)
        debug_log(results.text)
        
        # commit the changes
        debug_log("commit the changes")
        results = commit(args.leader, args.group, headers)
        debug_log(results.status_code)
        commit_id = results.json()['items'][0]['commit']
        debug_log("commit ID: " + commit_id)
        
        # deploy
        debug_log("deploy the changes from " + commit_id)
        results = deploy(args.leader, args.group,headers,commit_id)
        debug_log(results.status_code)
        debug_log(results.text)
        
        if results.status_code == 200:
            print("bueno")
        else:
            print("something happened")
    else:
        print("no update needed")
        sys.exit(0)
