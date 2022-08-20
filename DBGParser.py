import discord 
import os 
import config as cfg 
import zipfile 
import subprocess 
import tempfile 
import json
import requests
from datetime import datetime

# Made by Cpt-Dingus/Meti#7771
# Helped on by members of the r/TechSupport Discord server
print("v1.1.1 | 20-08-2022")

token = cfg.TOKEN
channel = ""
WINDBG_PATH = "C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x64\\windbg.exe"
URL = "No results detected!"
current_time = datetime.now().strftime("%H:%M:%S")
total_dump_no = 0


# Lowers the size of the windbg output to 1700 characters
EXCLUDES = ['Executable search', 'Kernel Base', 'Loading unloaded' 'Kernel base', '******', 'Bugcheck Analysis', '*    ', 'Loading User',    
           'Loading Unloaded', 'Opened log file', 'Microsoft', 'Copyright', 'Loading Dump', 'Mini Kernel Dump', 'Symbol search', 
             'NatVis','Windows 10', 'Product:', 'Edition', 'Machine', 'Debug session', 'System Uptime', 'ERROR_CODE', 'Arg2', 'Arg3', 'Arg4', 
             'Loading Kernel', '.......................', '!analyze', 'KEY', 'Key', 'Value', 'BUGCHECK', 'kd>', 
             'TRAP', '.trap', 'NOTE:', 'Some register values', 'rax', 'rdx', 'rip', 'r1', 'r2', 'r3', 'Kernel base', 
             'r4', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'r16', 'iop', 'scope', '......', 
             'exr', 'ExceptionAddress', 'ExceptionCode', 'ExceptionFlags', 'NumberParameters', 'Parameter',  
             'Subcode', 'BLACKBOXBSD', 'BLACKBOXNTFS', 'BLACKBOXPNP', 'BLACKBOXWINLOGON', 'EXCEPTION_CODE_STR', 'quit:', 
             'EXCEPTION_PARAMETER1', 'EXCEPTION_STR', 'STACK_COMMAND', 'BUCKET_ID', 'OS_VERSION', 'BUILDLAB_STR',
             'FAILURE_ID_HASH', 'IMAGE_VERSION', 'Loading unloaded module list', '!Analyze -v', 'analyze -v', 'OSPLATFORM_TYPE:']



def paste_file(file_path):
	global URL
 
	headers = {
		"Accept": "application/json",
		"Linx-Randomize": "yes",
	}

	with open(file_path, 'rb') as f:
		data = f.read()

	response = requests.put(f"https://paste.rtech.support/upload/{file_path}", headers=headers, data=data)
	json_output = response.content.decode("utf8")
	json_parsed = json.loads(json_output)
	URL = json_parsed["url"]



def process_dump_file(dump_file_path, timeout_seconds=60):
    # Bool to check if the file succeeded, string to check if file had a windbg error
    
	if not os.path.exists(dump_file_path):
		return False, ''

	if not dump_file_path.endswith(".dmp"):
		return False, ''

	with tempfile.TemporaryDirectory() as tmpdir:
		debug_output_file = os.path.join(tmpdir, "debug_output.txt")
  
		try:
			subprocess.check_output([WINDBG_PATH, "-zd", dump_file_path, "-c", "!analyze -v; q", "-logo", debug_output_file], timeout=timeout_seconds)
   
		except subprocess.TimeoutExpired:
			return False, 'FAIL'

		except subprocess.CalledProcessError:
			return False, ''

		filtered_result = ""

		with open(debug_output_file, 'r') as windbg_output:
      
			for line in windbg_output:
				line = line.strip()	 # Remove newlines
    
				if len(line) > 100 and ' : ' in line:  # Reduce stack trace
					tail = line.split(' : ', 1)[1]
					filtered_result += f"{tail}\n"
     
				elif "SYMBOL_NAME" in line:        # Separate stack trace from other important data
					head, sep, tail = line.partition("SYMBOL_NAME:")
					filtered_result += f"{head}\n\n----------\n{sep}{tail}"
     
				elif len(line) and not any(exclusion in line for exclusion in EXCLUDES):
					filtered_result += f"{line}\n"
     
		return filtered_result, 'OK'



def process_dumps_from_zip(dump_zip_path, max_dump_size_bytes=(1024*1024*100), timeout_seconds=45):
	global total_dump_no 
	total_dump_no = 0
 
	if not os.path.exists(dump_zip_path) or not os.path.isfile(dump_zip_path):
		return [], 0

	if not dump_zip_path.endswith(".zip"):
		return [], 0

	if not zipfile.is_zipfile(dump_zip_path):
		return [], 0

	dump_result_list = []
 
	with zipfile.ZipFile(dump_zip_path, 'r') as unzipped_path, tempfile.TemporaryDirectory() as tmpdir:
		
		for dump in unzipped_path.infolist():
			
			if not dump.filename.endswith(".dmp"): continue #  skip non-dump files
   
			if dump.file_size > max_dump_size_bytes: continue #  skip files that are above size limit
   
			total_dump_no += 1
			dump_path = os.path.join(tmpdir, f"{os.urandom(24).hex()}.dmp")
   
			with unzipped_path.open(dump, 'r') as file:
       
				with open(dump_path, 'wb') as dest_file:
					dest_file.write(file.read()) #  consumes up to max_dump_size_bytes memory

				dump_result, res = process_dump_file(dump_path, timeout_seconds=timeout_seconds)
    
				if res == 'FAIL': dump_result_list.append('FAIL')
				
				if dump_result: dump_result_list.append(dump_result)  # add dump result to list of dumps

	return dump_result_list, total_dump_no



class MyClient(discord.Client):

	async def on_ready(self):
		print("Logged in as {0}".format(self.user))

	async def on_message(self, message):
		if len(message.attachments) == 0: return

		for attach in message.attachments:
			filename = attach.filename
			client.get_channel(channel)
   
			if filename.endswith(".dmp"):
				dump_no = 1
    
				await message.channel.send(".dmp file detected! Processing...")
				print("Parsing dump file..")
    
				with tempfile.TemporaryDirectory() as tmpdir:
					dmp_file_name = os.path.join(tmpdir, f"{os.urandom(24).hex()}.dmp")
					await attach.save(fp=dmp_file_name)
					dump_result = process_dump_file(dmp_file_name)
    
					if dump_result:
						result_file_path = os.path.join(tmpdir, f"{os.urandom(24).hex()}txt")
      
						with open(result_file_path, "w") as results_file:
								results_file.write(f"{dump_result}")
        
						paste_file(result_file_path)
      
						await message.channel.send(f"Result: {URL}")
      
					else:
						print('Dump failed to debug')
						await message.channel.send("Dump failed to debug!")
      
      
			elif filename.endswith(".zip"):
       
				await message.channel.send(f"Zip file detected! Processing, this might a few minutes...")
				print("Parsing zip file..")
	
				with tempfile.TemporaryDirectory() as tmpdir:
					dmp_zip_path = os.path.join(tmpdir, f"{os.urandom(24).hex()}.zip")
		
					await attach.save(fp=dmp_zip_path)
					dump_results, total_dump_no = process_dumps_from_zip(dmp_zip_path)

					dump_no = 0  # Number of current dump for console prints
					dumps_ok = 0  # Number of succesful debug outputs for returned message
     
					result_file_path = os.path.join(tmpdir, f"{os.urandom(24).hex()}.txt")
					
					with open(result_file_path, 'w') as results_file:
						results_file.write(f"Debugged at: {current_time}\n")
	
					for result in dump_results:
						dump_no += 1
      
						result = "".join(result)
      
						with open(result_file_path, 'a') as results_file:  # Adds data to file
							results_file.write(f"\n{'-' * 20} Dump number {dump_no} {'-' * 20}\n")
							results_file.write(result)
       
						if result == 'FAIL':  
							print(f"Dump #{dump_no} FAIL")

						else:
							print(f"Dump #{dump_no} OK")
							dumps_ok += 1
		
					
					# Just for proper grammar in the returned message
					
					msg_str = "dumps"
					if dump_no == 1:
						msg_str = "dump"

					if len(dump_results) > 0:
						paste_file(result_file_path)
      
				await message.channel.send(f"{dumps_ok}/{total_dump_no} {msg_str} succesfully debuggedd\nResults: {URL}")
	
				total_dump_no = 0
					
					
if __name__ == '__main__':
	client = MyClient()
	client.run(token)
