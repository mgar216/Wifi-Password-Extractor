import subprocess, os, xmltodict, pprint, win32crypt

# Extract all avaialble passphrases into cleartext as XML files
stdout = subprocess.run('netsh wlan export profile key=clear', capture_output=True).stdout.decode()
all_files = [i.split('\"')[3].strip('.\\') for i in stdout.split('\n') if i != '\r' and i]

# Extract all passphrases from XML files and then delete the file itself
payload = {}
path = os.getcwd()
for file in all_files:
  with open(w := (path + '\\' + file), 'rb') as xml:
    data = xmltodict.parse(xml)['WLANProfile']
    if 'sharedKey' in data['MSM']['security']:
      passphrase = data['MSM']['security']['sharedKey']['keyMaterial']
      if passphrase.startswith('01000000D08C9DDF0115D1118C7'):
        passphrase = win32crypt.CryptBinaryToString(bytes(passphrase, encoding='utf8'), Flags=0)
      if data['name'] not in payload.keys():
        payload[data['name']] = [passphrase]
      else:
        payload[data['name']].append(passphrase)
  os.remove(w)

# Show results
pprint.pprint(payload)
