from pystyle import Colors, Colorate
from colorama import init
import base64
import utils
import zlib
import xdis
import ast
import sys
import re
import io
import os

init()

def get_pyc_vers_header(fstruct: dict) -> bytes:
  HEADERS = {
      310: b'\x6F\x0D\x0D\x0A'+b'\00'*12,
      311: b'\xA7\x0D\x0D'+b'\x00'*13,
      312: b'\xCB\x0D\x0D\x0A'+b'\00'*12
  }
  for i in fstruct:
    if 'python' in i and i.endswith('.dll') and not i == 'python3.dll':
      ver = ''.join(re.findall(r'\d+', i))
      if sys.version_info[1] != int(ver[1:]):
        print(Colors.purple+f'[-] Please Run This Script With Python {ver[:1]}.{ver[1:]}')
        sys.exit()
      return HEADERS[int(ver)]

try:
  from tkinter import filedialog as fd
  executable = fd.askopenfilename(title="Select file to decompile")
except ImportError:
  executable = input('File path: ')
  
if not os.path.exists(executable):
  print(Colors.purple+'[-] Invalid File')
  sys.exit()
        
extracted = utils.Extract(executable)

print(Colors.purple+'[*] Loading The PYC')

loaded: tuple = xdis.load_module_from_file_object(io.BytesIO(get_pyc_vers_header(extracted)+b'\xE3'+extracted['loader-o'].split(b'\xE3', 1)[-1]))
version: tuple = loaded[0]
code_obj: xdis.Code13 = loaded[3]
ispypy: bool = loaded[4]
insts: list[xdis.Instruction] = list(xdis.Bytecode(code_obj, xdis.get_opcode(version, ispypy)).get_instructions(code_obj))

print(Colors.purple+'[*] PYC Loaded Succesfully')

cleared = []
for i in insts:
  if i.opname!='CACHE':
    cleared.append(i)

def Get_Layer_Pyc(insts: list[xdis.Instruction]) -> str:
  """
  Get the current layer of obfuscation for compiled obf
  """
  for i in range(len(insts)):
    cur: xdis.Instruction = insts[i]
    if 'IF' in cur.opname:
      return 'l2'
  return 'l1'


def Get_Layer(code: str) -> dict:
  """
  Get the current layer of obfuscation for plain obf
  """
  if re.findall(r'\(\D+ \+ \D+ \+ \D+ \+ \D+\)', code):
    return 'l1'
  elif re.findall(r'\^ .+ == .+', code):
    return 'l2'
  elif re.findall(r'[\D]+ = \[[\'\d., ]+\]', code):
    return 'l3'
  else:
    raise Exception('This file is not obfuscated with BlankObfV2')


def Layer_1_PYC(insts: list[xdis.Instruction]) -> str:
  """
  Deobfuscate the compiled Layer 1 of BlankObfV2
  """
  print(Colors.purple+'[*] Deobfuscating pyc layer1')
  base: list[list[tuple, int, int]] = []
  for i in range(len(insts)):
    cur: xdis.Instruction = insts[i]
    if not isinstance(cur.argval, tuple):continue
    if len(cur.argval) > 1000:
      base.append([cur.argval, insts[i+12].argval, insts[i+13].argval])
  _ = base[0][0][::-1][base[0][1]:base[0][2]]
  __ = base[1][0][::-1][base[1][1]:base[1][2]]
  ___ = base[2][0][::-1][base[2][1]:base[2][2]]
  ____ = base[3][0][::-1][base[3][1]:base[3][2]]
  all = _+__+___+____
  found = ''.join(map(chr, all))
  return zlib.decompress(base64.b64decode(found)).decode(errors='replace')


def Layer_2_PYC(insts: list[xdis.Instruction]) -> str:
  """
  Deobfuscate the compiled Layer 2 of BlankObfV2
  """
  for i in range(len(insts)):
    cur: xdis.Instruction = insts[i]
    if isinstance(cur.argval, tuple):
      if len(cur.argval) > 1000:
        base: tuple = cur.argval
    if cur.opname == 'POP_JUMP_IF_FALSE' or cur.opname == 'POP_JUMP_FORWARD_IF_FALSE':
      print(insts[i-9].argval)
      print(insts[i-4].argval)
      in_loc = insts[i-9].argval
      re_loc = insts[i-4].argval
    if cur.opname == 'POP_JUMP_IF_TRUE' or cur.opname == 'POP_JUMP_FORWARD_IF_TRUE':
      in_loc = insts[i-8].argval
      re_loc = insts[i-3].argval
  for it1 in range(1,100):
    if base[in_loc] ^ it1 == base[re_loc]:
      last=zlib.decompress(bytes(map(lambda arg1: arg1 ^ it1, base[0:in_loc] + base[in_loc+1:re_loc] + base[re_loc+1:]))).decode(errors='replace')
  return last


def Layer_1_Plain(code: str) -> str:
  """
  Deobfuscate The Layer 1 Plain Code Of BlankObfV2
  """
  print(Colors.purple+'[*] Deobfuscating layer1')
  slices = re.findall(r'\.decode\(\)\[[\d \-()+/:]+\]', code)
  tree = ast.parse(code)
  byte: list[ast.Call] = []
  for i in ast.walk(tree):
    if not isinstance(i, ast.Call):continue
    if not isinstance(i.func, ast.Name):continue
    if i.func.id != 'bytes':continue
    byte.append(i)
  important: list[list[ast.Constant]] = []
  for i in byte:
    lst = i.args[0].value.elts
    if len(lst) < 500:continue
    important.append(lst)
  _ = bytes([i.value for i in important[0]][::-1]).decode()[eval(slices[0].split('[')[-1].split(']')[0].split(':')[0]):eval(slices[0].split('[')[-1].split(']')[0].split(':')[1])]
  __ = bytes([i.value for i in important[1]][::-1]).decode()[eval(slices[1].split('[')[-1].split(']')[0].split(':')[0]):eval(slices[1].split('[')[-1].split(']')[0].split(':')[1])]
  ___ = bytes([i.value for i in important[2]][::-1]).decode()[eval(slices[2].split('[')[-1].split(']')[0].split(':')[0]):eval(slices[2].split('[')[-1].split(']')[0].split(':')[1])]
  ____ = bytes([i.value for i in important[3]][::-1]).decode()[eval(slices[3].split('[')[-1].split(']')[0].split(':')[0]):eval(slices[3].split('[')[-1].split(']')[0].split(':')[1])]
  return zlib.decompress(base64.b64decode(_+__+___+____)).decode(errors='replace')


def Layer_2_Plain(code: str) -> str:
  """
  Deobfuscate The Layer 2 Plain Code Of BlankObfV2
  """
  print(Colors.purple+'[*] Deobfuscating layer2')
  obfuscated=eval('[' + re.findall(r'[\D]+ = \[[\d.,+/\-() ]+\]', code)[0].split('[')[-1])
  loc = re.findall(r'\[[\d+ /\-()]+\]', re.findall(r'if .+:', code)[0])
  in_loc = eval(loc[0].replace('[',' ').replace(']', ''))
  re_loc = eval(loc[1].replace('[', '').replace(']', ''))
  for it1 in range(1, 100):
    if obfuscated[in_loc] ^ it1 == obfuscated[re_loc]:
      kaka=zlib.decompress(bytes(map(lambda arg1: arg1 ^ it1, obfuscated[0:in_loc] + obfuscated[in_loc+1:re_loc] + obfuscated[re_loc+1:])))
      break
  return kaka.decode(errors='replace')


def Layer_3_Plain(code) -> str:
  """
  Deobfuscate The Layer 3 Plain Code Of BlankObfV2
  """
  print(Colors.purple+'[*] Deobfuscating layer3')
  obfuscated = eval('['+re.findall(r'[\D]+ = \[[\'\d., ]+\]', code)[0].split('[')[-1])
  deobfuscated = ''
  for i in obfuscated:
    for _ in i.split('.'):
      deobfuscated=deobfuscated+chr(int(_))
  return zlib.decompress(base64.b64decode(deobfuscated)).decode()


def Plain_Deobf(code: str) -> str:
  """
  Main deobf for plain
  """
  if """:: You managed to break through BlankOBF v2; Give yourself a pat on your back! ::""" in code:
    return code
  else:
    match Get_Layer(code):
      case 'l1':
        return Plain_Deobf(Layer_1_Plain(code))
      case 'l2':
        return Plain_Deobf(Layer_2_Plain(code))
      case 'l3':
        return Plain_Deobf(Layer_3_Plain(code))


def Compiled_Deobf(insts: list[xdis.Instruction]) -> str:
  """
  Main deobf for compiled
  """
  layer = Get_Layer_Pyc(insts)
  match layer:
    case 'l1':
      return Layer_1_PYC(insts)
    case 'l2':
      return Layer_2_PYC(insts)


def Extract_Config(code: str) -> str:
  """
  Extract the config from deobfuscated file
  """
  if '__CONFIG__'in code:
    for i in code.split('\n'):
      if '__CONFIG__ = ' in i:
        # Ungrabber regex leak :D
        return re.findall(r'https:\/\/(?:canary\.)?(?:ptb\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]+', i)[0]

if __name__ == '__main__':
  webhook = Extract_Config(Plain_Deobf(Compiled_Deobf(cleared)))
  print(Colors.purple+f'[+] Webhook: {webhook}')
