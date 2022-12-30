# Made by Cpt-Dingus/Meti#7771
# Helped on by members of the r/TechSupport Discord server
print("v1.2 | 30-12-2022")


import discord 
from discord.ext import commands
import os 
import config as cfg 
import zipfile 
import subprocess 
import tempfile 
import json
import requests
from datetime import datetime



# --- Vars ---

token = cfg.TOKEN
bot = commands.Bot(command_prefix='!',intents=discord.Intents.all()) # ALT PREFIX = !
WINDBG_PATH = "C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x64\\windbg.exe"
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

if not os.path.exists(WINDBG_PATH): raise FileNotFoundError('''10 -> Windbg not found, make sure the x64 version of the STANDARD (Not preview!) WinDBG editor is installed at
"C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x64\\windbg.exe"''')


# --- Defs ---

def paste_file(file_path):

	headers = {
		"Accept": "application/json",
		"Linx-Randomize": "yes"}

	with open(file_path, 'r') as f:
		data = f"{f.read()}".replace(r'\n', '\n')


	response = requests.put(f"https://paste.rtech.support/upload/{file_path}", headers=headers, data=data)
	json_parsed = json.loads(response.content.decode("utf8"))
	return json_parsed["url"]



def process_dump_file(dump_file_path, timeout_seconds=60):
    # RETURNS:
	#  -> Bool to check if the file succeeded
	#  -> String to check if file had a windbg error
    
	if not os.path.exists(dump_file_path) or not dump_file_path.endswith(".dmp"):
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
				
				if line == '\n': continue  # Removes newlines
    
    
				elif len(line) > 100 and ' : ' in line:  # Reduce stack trace
					tail = line.split(' : ', 1)[1]
					filtered_result += f"{tail}"
     
				elif "SYMBOL_NAME" in line:        # Separate stack trace from other important data
					head, sep, tail = line.partition("SYMBOL_NAME:")
					filtered_result += f"{head}\n----------\n{sep}{tail}"
     
				elif not any(exclusion in line for exclusion in EXCLUDES):
					filtered_result += f"{line}"
     
    
		return filtered_result, 'OK'



def process_dumps_from_zip(dump_zip_path, max_dump_size_bytes=(1024*1024*100), timeout_seconds=45):
    # RETURNS:
    #  -> List of all debugging results
    #  -> Number of all dump files
    
	global total_dump_no 
	total_dump_no = 0
 
	if not os.path.exists(dump_zip_path) or not os.path.isfile(dump_zip_path) or not dump_zip_path.endswith(".zip")\
    or not zipfile.is_zipfile(dump_zip_path):
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




# --- Main ---

@bot.hybrid_command(name="debug-files", description="Debugs a .dmp or a .zip containing .d	mp files, posts link with windbg output")
async def debug_files(ctx, file: discord.Attachment):	
	if len(ctx.message.attachments) == 0:	
		await ctx.send("No attachments found")	
	
	for attach in ctx.message.attachments:	
		filename = attach.filename	
	
		if filename.endswith(".dmp"):	
			dump_no = 1	
	
			await ctx.send(".dmp file detected! Processing...")	
			print("Parsing dump file..")	
	
			with tempfile.TemporaryDirectory() as tmpdir:	
				dmp_file_name = os.path.join(tmpdir, f"{os.urandom(24).hex()}.dmp")	
				await attach.save(fp=dmp_file_name)	
				dump_result, res = process_dump_file(dmp_file_name)
				print(dump_result)
				if res == 'OK':
					result_file_path = os.path.join(tmpdir, f"{os.urandom(24).hex()}txt")
	
					with open(result_file_path, "w") as results_file:
							results_file.write(f"Debugged at: {current_time}\n")
							results_file.write(f"{dump_result}")
	
	
					await ctx.send(f"Result: {paste_file(result_file_path)}")
	
				else:
					print('Dump failed to debug')
					await ctx.send("Dump debugging failed!")
	

		elif filename.endswith(".zip"):
		
			await ctx.send(f"Zip file detected! Processing, this might take a few minutes...")
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

					result = "".join(result)	# Converts result to a string

					with open(result_file_path, 'a') as results_file:  # Adds results to file
						results_file.write(f"\n{'-' * 20} Dump number {dump_no} {'-' * 20}\n")
						results_file.write(result)

					if result == 'FAIL':  
						print(f"Dump #{dump_no} FAIL")

					else:
						print(f"Dump #{dump_no} OK")
						dumps_ok += 1


				dump_str = "dump"
				if dump_no > 1: dump_str = "dumps"

				if len(dump_results) > 0:
				
					await ctx.send(f"{dumps_ok}/{total_dump_no} {dump_str} succesfully debugged\nResults: {paste_file(result_file_path)}")

				else:
					await ctx.send(f"None out of {total_dump_no} dumps succesfully debugged")

				total_dump_no = 0
					
				

@bot.event
async def on_ready():
	await bot.tree.sync()
	print(f"Logged in as {bot.user}")



if __name__ == '__main__':	bot.run(token)
