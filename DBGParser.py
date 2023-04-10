# Made by Cpt-Dingus/Meti#7771
# Helped on by members of the r/TechSupport Discord server
print("v1.2.1 | 10-04-2023")


import config as cfg
from datetime import datetime
import discord
from discord.ext import commands
import json
import os
import requests
import subprocess
import tempfile
import zipfile

# --- Vars ---

token = cfg.TOKEN
bot = commands.Bot(command_prefix='!',intents=discord.Intents.all()) # ALT PREFIX = !
current_time = datetime.now().strftime("%H:%M:%S")
total_dump_no = 0

# Lowers the size of the windbg output to 1700 characters by excluding junk
EXCLUDES = ['!Analyze -v', '!analyze', '*    ', '******', '......', '.......................', '.trap', 'Arg2', 'Arg3', 'Arg4', 'BLACKBOXBSD', 'BLACKBOXNTFS', 'BLACKBOXPNP',
            'BLACKBOXWINLOGON', 'BUCKET_ID', 'BUGCHECK', 'BUILDLAB_STR', 'Bugcheck Analysis', 'Copyright', 'Debug session', 'ERROR_CODE', 'EXCEPTION_CODE_STR',
            'EXCEPTION_PARAMETER1', 'EXCEPTION_STR', 'Edition', 'ExceptionAddress', 'ExceptionCode', 'ExceptionFlags', 'Executable search', 'FAILURE_ID_HASH', 'IMAGE_VERSION',
            'KEY', 'Kernel Base', 'Kernel base', 'Key', 'Loading Dump', 'Loading Kernel', 'Loading Unloaded', 'Loading User', 'Loading unloaded module list',
            'Loading unloadedKernel base', 'Machine', 'Microsoft', 'Mini Kernel Dump', 'NOTE:', 'NatVis', 'NumberParameters', 'OSPLATFORM_TYPE:', 'OS_VERSION',
            'Opened log file', 'Parameter', 'Product:', 'STACK_COMMAND', 'Some register values', 'Subcode', 'Symbol search', 'System Uptime', 'TRAP', 'Value',
            'Windows 10', 'analyze -v', 'exr', 'iop', 'kd>', 'quit:', 'r1', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'r16', 'r2', 'r3', 'r4', 'r6', 'r7', 'r8',
            'r9', 'rax', 'rdx', 'rip', 'scope']




# --- Checks ---

if os.path.exists("C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x64\\windbg.exe"): 
	WINDBG_PATH = "C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x64\\windbg.exe"
else:
	print("x64 version of WinDBG not found, checking for x32 version...")
	if os.path.exists("C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x32\\windbg.exe"):
		WINDBG_PATH = "C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x32\\windbg.exe"
	
	else:
		raise FileNotFoundError('''Windbg not found, make sure the STANDARD (Not preview!) WinDBG 
is installed at "C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x64\\windbg.exe"''')
		


# --- Defs ---

def paste_file(txt_file_path):
    # Shoves the output into the rtech.support api
    # Params:
    #  -> txt_file_path (str) = Path to the .txt file to paste
	#
	# Returns:
	#  -> (str) URL of the paste
 
	headers = {
		"Accept": "application/json",
		"Linx-Randomize": "yes"}

	with open(txt_file_path, 'r') as file:
		data = f"{file.read()}".replace(r'\n', '\n') # Makes sure there aren't any raw newlines

	response = requests.put(f"https://paste.rtech.support/upload/{txt_file_path}", headers=headers, data=data)
	json_parsed = json.loads(response.content.decode("utf8"))
	return json_parsed["url"]



def process_dump_file(dump_file_path, timeout_seconds=60):
    # Debugs a singular dump file
    # Params:
    #  -> (str) dump_file_path = Path to the target .dmp file
    #  -> (int) timeout_seconds = Number of seconds to stop debugging after (in case of a hang)
    # 
    # Returns:
	#  -> (bool) Check if the file succeeded
	#  -> (str) Check if file had a windbg error happen
    
    # Checks if the dump file path and file are valid
	if not os.path.exists(dump_file_path) or not dump_file_path.endswith(".dmp"):
		return False, ''

	# Tempdir used for storing all files
	with tempfile.TemporaryDirectory() as tmpdir:
		debug_output_file = os.path.join(tmpdir, "debug_output.txt")
  
		# Runs a windbg commnad for a specified amount of seconds
		try:
			subprocess.check_output([WINDBG_PATH, "-zd", dump_file_path, "-c", "!analyze -v; q", "-logo", debug_output_file], timeout=timeout_seconds)
   
		# DBG Hang prevention in case of an invalid dump
		except subprocess.TimeoutExpired:
			return False, 'FAIL'

		except subprocess.CalledProcessError:
			return False, ''

		filtered_result = ""

		with open(debug_output_file, 'r') as windbg_output:
      
			for line in windbg_output:
				
				if line == '\n': continue  # Removes newlines
    
				# Reduces the stack trace by excluding the first half of junk
				elif len(line) > 100 and ' : ' in line:  
					tail = line.split(' : ', 1)[1]
					filtered_result += f"{tail}"
     
				# Separates the stack trace from other important data
				elif "SYMBOL_NAME" in line:        
					head, sep, tail = line.partition("SYMBOL_NAME:")
					filtered_result += f"{head}\n----------\n{sep}{tail}"

				# Removes pointless data from the stack trace
				elif not any(exclusion in line for exclusion in EXCLUDES):
					filtered_result += f"{line}"


		return filtered_result, 'OK'



def process_dumps_from_zip(dump_zip_path, max_dump_size_bytes=(1024*1024*100), timeout_seconds=45):
    # Debugs a singular dump file
    # Params:
    #  -> (str) dump_zip_path = Path to the target .zip file
    #  -> (int) max_dump_size_bytes = Maximum size for a dump file for security
    #  -> (int) timeout_seconds = Number of seconds to stop debugging after (in case of a hang)
    #
    # Returns:
    #  -> (list) Results of all dumps
	#  -> (int) Number of all dump files
	
	# Global for the return command
	global total_dump_no
	total_dump_no = 0

	# Checks if the zip path and file is valid
	if not os.path.exists(dump_zip_path) or not os.path.isfile(dump_zip_path) or not dump_zip_path.endswith(".zip")\
    or not zipfile.is_zipfile(dump_zip_path):
		return [], 0


	dump_result_list = []
 
	with zipfile.ZipFile(dump_zip_path, 'r') as unzipped_path, tempfile.TemporaryDirectory() as tmpdir:
		
		for dump in unzipped_path.infolist():
      
			# Skips any files that are higher than the size limit or are non-dump files
			if not dump.filename.endswith(".dmp") or dump.file_size > max_dump_size_bytes: continue #  skip non-dump files
   
			total_dump_no += 1
			dump_path = os.path.join(tmpdir, f"{os.urandom(24).hex()}.dmp")
   
			with unzipped_path.open(dump, 'r') as file:
       
				with open(dump_path, 'wb') as dest_file:
        			# Consumes up to max_dump_size_bytes memory
					dest_file.write(file.read()) 

				dump_result, res = process_dump_file(dump_path, timeout_seconds=timeout_seconds)

				# Adds the dump result (or the lack thereof) to the list of dump results
				if res == 'FAIL': dump_result_list.append('FAIL')
				if dump_result: dump_result_list.append(dump_result)  

	return dump_result_list, total_dump_no




# --- Main ---

@bot.hybrid_command(name="debug-file", description="Debugs a .dmp or a .zip containing .dmp files, posts link with windbg output")
async def debug_file(ctx, file: discord.Attachment):	
	if len(ctx.message.attachments) == 0:	
		await ctx.send("No attachments found")	
	
	for attach in ctx.message.attachments:	
		filename = attach.filename	
	
		if filename.endswith(".dmp"):	
			dump_no = 1	
	
			await ctx.send(".dmp file detected! Processing...")	
			print("Parsing dump file..")	

			# Creates a temp directory for the files
			with tempfile.TemporaryDirectory() as tmpdir:	
				# Creates a file path and downloads the dump file to it
				dmp_file_name = os.path.join(tmpdir, f"{os.urandom(24).hex()}.dmp")	
				await attach.save(fp=dmp_file_name)

				dump_result, res = process_dump_file(dmp_file_name)
				print(dump_result)
				if res == 'OK':
					result_file_path = os.path.join(tmpdir, f"{os.urandom(24).hex()}txt")

					# Creates a result file path, writes the result to it
					with open(result_file_path, "w") as results_file:
							results_file.write(f"Debugged at: {current_time}\n")
							results_file.write(f"{dump_result}")
	
					# Pastes the result and send it to the chat.
					await ctx.send(f"Result: {paste_file(result_file_path)}")
	
				else:
					print('Dump failed to debug')
					await ctx.send("Dump debugging failed!")



		elif filename.endswith(".zip"):
		
			await ctx.send(f"Zip file detected! Processing, this might take a few minutes...")
			print("Parsing zip file..")

			# Creates a temp directory for the files
			with tempfile.TemporaryDirectory() as tmpdir:
       			# Creates a file path and downloads the zip file into it
				dmp_zip_path = os.path.join(tmpdir, f"{os.urandom(24).hex()}.zip")
				await attach.save(fp=dmp_zip_path)

				dump_no = 0  # Number of current dump for console prints
				dumps_ok = 0  # Number of succesful debug outputs for returned message
				result_file_path = os.path.join(tmpdir, f"{os.urandom(24).hex()}.txt")
				
				with open(result_file_path, 'w') as results_file:
					results_file.write(f"Debugged at: {current_time}\n")

				dump_results, total_dump_no = process_dumps_from_zip(dmp_zip_path)


				for result in dump_results:
					dump_no += 1
				    # Converts result to a string
					result = "".join(result) 

					# Adds results to file
					with open(result_file_path, 'a') as results_file:  
						results_file.write(f"\n{'-' * 20} Dump number {dump_no} {'-' * 20}\n")
						results_file.write(result)

					if result == 'FAIL':  
						print(f"Dump #{dump_no} FAIL")

					else:
						print(f"Dump #{dump_no} OK")
						dumps_ok += 1

				# Formatting for the return message because pretty
				dump_str = "dump"
				if dump_no > 1: dump_str = "dumps"

				if len(dump_results) > 0:				
					await ctx.send(f"{dumps_ok}/{total_dump_no} {dump_str} succesfully debugged\nResults: {paste_file(result_file_path)}")

				else:
					await ctx.send(f"None out of {total_dump_no} {dump_str} succesfully debugged")

				total_dump_no = 0
					
				

@bot.event
async def on_ready():
    # Makes slash commands available
	await bot.tree.sync()
	print(f"Logged in as {bot.user}")



if __name__ == '__main__':	bot.run(token)
