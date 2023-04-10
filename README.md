### Bot that uses discord.py to parse .dmp files (zipped dump files supported)

Uses:
* Discord.ext as the backend
* The paste.rtech.support API for output
* A slash command to debug, with `!` as backup


# To set up & use
1) Make sure the x64 bit version of WinDBG (Not the preview!) is installed
2) Create config.py according to the template in the same directory as DBGparser.py, fill in your bot's API token as well as the channel for sending the output
3) Run DBGparser.py

Usage:
1) Run `/debug_file` OR `!debug_file` with a .dmp file or a .zip file containing .dmp files attached
2) Open the returned link for the debugger output



Made for and by the r/TechSupport community
