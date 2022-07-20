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
print('v1.0.4 | 20-07-2022')

token = cfg.TOKEN
channel = ''
WINDBG_PATH = 'C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x64\\windbg.exe'
URL = "No results parsed!"
current_time = datetime.now().strftime("%H:%M:%S")


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
             'FAILURE_ID_HASH', 'IMAGE_VERSION', 'Loading unloaded module list', '!Analyze -v', '"analyze -v', 'OSPLATFORM_TYPE:']


def list_to_string(input_list): 
    output_str = ""
    return (output_str.join(input_list))


def paste_file(file_path):
	global URL
	headers = {
		'Accept': 'application/json',
		'Linx-Randomize': 'yes',
	}

	with open(file_path, 'rb') as f:
		data = f.read()

	response = requests.put(f'https://paste.rtech.support/upload/{file_path}', headers=headers, data=data)
	json_output = response.content.decode('utf8')
	json_parsed = json.loads(json_output)
	URL = json_parsed['url']


def process_dump_file(dump_file_path, timeout_seconds=60):
	if not os.path.exists(dump_file_path):
		return False

	if not dump_file_path.endswith(".dmp"):
		return False

	with tempfile.TemporaryDirectory() as tmpdir:
		debug_output_file = os.path.join(tmpdir, "debug_output.txt")
  
		try:
			proc = subprocess.check_output([WINDBG_PATH, '-zd', dump_file_path, '-c', '!analyze -v; q', '-logo', debug_output_file], timeout=timeout_seconds)
   
		except subprocess.TimeoutExpired:
			return False

		except subprocess.CalledProcessError:
			return False

		filtered_output = ""

		with open(debug_output_file, 'r') as debug_file:
			for line in debug_file:
				line = line.strip()
				if len(line) > 100 and ' : ' in line:
					tail = line.split(' : ', 1)[1]
					filtered_output += tail + "\n"
				elif 'SYMBOL_NAME' in line:
					head, sep, tailA = line.partition('SYMBOL_NAME:')
					separator_format = '\n\n' + '----------' + '\n'
					filtered_output += head + separator_format + sep + tailA
				elif len(line) and not any(exclusion in line for exclusion in EXCLUDES):
					filtered_output += line + "\n"
		return filtered_output


def process_dump_zip(dump_zip_path, max_dump_size_bytes=(1024*1024*100), timeout_seconds=45):
	""" Processes all dumps in a zip """

	if not os.path.exists(dump_zip_path) or not os.path.isfile(dump_zip_path):
		return []

	if not dump_zip_path.endswith(".zip"):
		return []

	if not zipfile.is_zipfile(dump_zip_path):
		return []

	dumps = []

	with zipfile.ZipFile(dump_zip_path, 'r') as dump_zip, tempfile.TemporaryDirectory() as tmpdir:
		for fileinfo in dump_zip.infolist():
			if not fileinfo.filename.endswith(".dmp"): continue # skip non-dump files
			if fileinfo.file_size > max_dump_size_bytes: continue # skip files that are above size limit

			dest_file_name = os.path.join(tmpdir, "%s.dmp" % os.urandom(24).hex())
			with dump_zip.open(fileinfo, 'r') as file:
				with open(dest_file_name, 'wb') as dest_file:
					dest_file.write(file.read()) # will consume up to max_dump_size_bytes memory

				dump = process_dump_file(dest_file_name, timeout_seconds=timeout_seconds)
				if dump: dumps.append(dump) # add dump if valid to list of dumps

	return dumps


class MyClient(discord.Client):
	async def on_ready(self):
		print('Logged in as {0}'.format(self.user))

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
					dmp_file_name = os.path.join(tmpdir, "%s.dmp" % os.urandom(24).hex())
					await attach.save(fp=dmp_file_name)
					dump_info = process_dump_file(dmp_file_name)
    
					if dump_info:
						result_file_path = os.path.join(tmpdir, "%s.txt" % os.urandom(24).hex())
      
						with open(result_file_path, "w") as results_file:
								results_file.write("%s" % dump_info)
						paste_file(result_file_path)
      
						await message.channel.send(f"Result: {URL}")
      
      
			elif filename.endswith(".zip"):
				await message.channel.send(f"Zip file detected! Processing, this might a few minutes...")
				print("Parsing zip file..")
				with tempfile.TemporaryDirectory() as tmpdir:
					dmp_zip_name = os.path.join(tmpdir, "%s.zip" % os.urandom(24).hex())
					await attach.save(fp=dmp_zip_name)
					dump_infos = process_dump_zip(dmp_zip_name)
     
					for i in range(len(dump_infos)):
						dump_info = list_to_string(dump_infos[i])
						result_file_path = os.path.join(tmpdir, "%s.txt" % os.urandom(24).hex())
      
						with open(result_file_path, "w") as results_file:
							results_file.write("Parsed at: %s\n" % current_time)
       
						dump_no = 0
						for i in dump_infos:
							dump_no += 1
							with open(result_file_path, "a") as results_file: # Adds data to file
								info_text = "\n--------------------" + f'Dump number {dump_no}' + "--------------------\n"
								results_file.write(info_text)
								results_file.write(dump_info)
							paste_file(result_file_path)
						dump_str = 'dumps'
						if dump_no == 1:
							dump_str = 'dump'
				await message.channel.send(f'{dump_no} {dump_str} parsed\nResults: {URL}')
					
					
if __name__ == '__main__':
	client = MyClient()
	client.run(token)