import paramiko, traceback
host = "locolhost"
port = 2222
user = "foo"
pw = "pass"

try:
    t = paramiko.Transport((host, port))
    t.connect(username=user, password=pw)
    sftp = paramiko.SFTPClient.from_transport(t)
    print("Connected OK. Remote dir listing:")
    print(sftp.listdir('.'))
    sftp.close()
    t.close()
except Exception:
    print("Paramiko error:")
    traceback.print_exc()