r"""try_sftp_put.py

Usage examples (PowerShell):
    python try_sftp_put.py --host 127.0.0.1 --port 2222 --user foo --password pass --local "D:\\Phishing\\Phishing\\storage\\file.pdf" --remote /home/foo/file.pdf

Supports password or key auth (provide --key <path> and optional --passphrase).
Prints detailed exception tracebacks to help debug Paramiko issues on Windows.
"""
import argparse
import paramiko
import os
import traceback
import posixpath

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--host', required=True)
    p.add_argument('--port', type=int, default=22)
    p.add_argument('--user', required=True)
    p.add_argument('--password')
    p.add_argument('--key')
    p.add_argument('--passphrase')
    p.add_argument('--local', required=True)
    p.add_argument('--remote', required=True)
    args = p.parse_args()

    local = args.local
    print('Local path repr:', repr(local))
    print('Exists:', os.path.exists(local))
    if os.path.exists(local):
        print('Size:', os.path.getsize(local))

    try:
        transport = paramiko.Transport((args.host, args.port))
        if args.key:
            try:
                pkey = paramiko.RSAKey.from_private_key_file(args.key, password=args.passphrase)
            except Exception:
                try:
                    pkey = paramiko.Ed25519Key.from_private_key_file(args.key, password=args.passphrase)
                except Exception:
                    pkey = None
            if pkey is None:
                print('Failed to load private key')
                return
            transport.connect(username=args.user, pkey=pkey)
        else:
            transport.connect(username=args.user, password=args.password)

        sftp = paramiko.SFTPClient.from_transport(transport)
        try:
            rcwd = None
            try:
                rcwd = sftp.getcwd()
            except Exception:
                rcwd = None
            print('Connected. Remote cwd:', rcwd)

            # ensure remote parent directory exists
            remote_parent = posixpath.dirname(args.remote)
            if remote_parent:
                parts = [p for p in remote_parent.split('/') if p]
                cur = '/' if args.remote.startswith('/') else ''
                for part in parts:
                    cur = posixpath.join(cur, part)
                    try:
                        sftp.stat(cur)
                    except IOError:
                        try:
                            sftp.mkdir(cur)
                        except Exception as e:
                            print('Failed to create remote dir', cur, e)
            tried_paths = []
            def try_put(path):
                tried_paths.append(path)
                try:
                    sftp.put(local, path)
                    print('Upload succeeded to', path)
                    return True
                except Exception as e:
                    print('Upload failed for', path, ':', e)
                    traceback.print_exc()
                    return False

            succeeded = try_put(args.remote)
            if not succeeded:
                # fallback: try relative uploads/ path
                rel = args.remote.lstrip('/')
                rel_alt = rel if rel else f"uploads/{os.path.basename(local)}"
                if not rel_alt.startswith('uploads'):
                    rel_alt = posixpath.join('uploads', os.path.basename(rel_alt))
                print('Attempting fallback remote path:', rel_alt)
                # try create relative dir if missing
                try:
                    try:
                        sftp.stat('uploads')
                    except Exception:
                        try:
                            sftp.mkdir('uploads')
                        except Exception as e:
                            print('Failed to create relative uploads dir:', e)
                    succeeded = try_put(rel_alt)
                except Exception as e:
                    print('Fallback attempt failed:', e)
        finally:
            sftp.close()
            transport.close()
    except Exception as e:
        print('Connection/setup failed:', e)
        traceback.print_exc()

if __name__ == '__main__':
    main()
