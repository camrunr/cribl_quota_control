# cribl_quota_control
A script to check your daily logging total for a destination, and react if you're over quota

# What it does
Using the Cribl API, the script does the following in sequence:
- Retrieve the current volume sent by the specified destination so far today
- Retrieve the current flag (global variable) setting, `true` or `false`
- If the current volume is over the specified quota, and the current flag is false, update the flag to true
  - this indicates we are over license quota and should stop sendning to the destination
- If the current volume is under the specified quota, and the current flag is true, update the flag to false
  - this indicates we have started a new day and we need to disable the block

# How to set-up Cribl Stream

3 Assumptions:
- You have an existing destination you'd like to control usage of on a daily basis
- You are already sending a copy of all your logs to a data lake or other secondaary destination
  - So when we drop the overage, you still have access to them!
- You have created an admin level API token in Cribl Cloud, or have an admin level user in a self-managed install

With those rules in mind:
- Create a Global Variable called `quotaDetour` or whatever name catches your fancy
   - It should be a boolean type
- Create a new Output Router destination
- Create a rule for the case of sending to your existing destination
  - Set the filter to `!quotaDetour` and mark it Final
- Change your route(s) to point to the Output Router as destination

Alternative!
If you do not currently copy all of your data into a data lake, you could make 2 destination entries. 
- First rule as above that delivers to your SIEM when under quota
- Second rule points to a different destination, allowing you to collect the overage logs ... somewhere else

There are plenty of other ways to achieve this goal! You can reference GVs in the routing table, for example. Choose the method that works best for you.

# Running the script
The script requires python 3 and the requests module. You run it with a series of flags to define the variables required.

`usage: cribl_quota_control.py [-h] [-D] -l LEADER -g GROUP -n VARNAME -o OUTPUTID -q QUOTAGB -u USERNAME [-P PASSWORD]`

Flags:
- `-h` displays a usage message
- `-D` turns on debug logging to stdout
- `-l` define the leader url; for cloud this will be something like `https://main-<yourinstance>.cribl.cloud`
- `-g` define which group we're working on
- `-n` define the global variable name
- `-o` define the output id; this will be in the form of `output_type`:`name`
- `-q` define the max GBs you want to allow before we block (daily)
- `-u` the client id or username
- `-P` the client secret or password

A sample run:    
`uv run quota_trap.py -u <client_id> -P <client_secret> -n quotaDetour -o tcp:mysiem -q 1000 -g default -l https://main-<myinstance>.cribl.cloud`

If you leave off username and/or password, you will be prompted to enter them.

Once you have validated it's working, you can schedule it to run via cron or systemd timers. How frequently you run it depends on how reactive you want to be.

This is a side project of mine, and not endorsed by Cribl. Use at your own risk!

Fork it and chop it up how you like. If you fix something or do something cool, please issue a PR.

