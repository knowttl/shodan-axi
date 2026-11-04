import { execFileSync } from 'node:child_process'
import { mkdir, writeFile } from 'node:fs/promises'
import { join } from 'node:path'

export async function createTestTls(root, hostname) {
  const keyFile = join(root, 'key.pem'); const certFile = join(root, 'cert.pem')
  const requestFile = join(root, 'request.pem'); const configFile = join(root, 'authority.cnf')
  await mkdir(join(root, 'issued'))
  await writeFile(join(root, 'index.txt'), '')
  await writeFile(join(root, 'serial.txt'), '01\n')
  await writeFile(configFile, `[ca]\ndefault_ca=authority\n[authority]\ndatabase=${join(root, 'index.txt')}\nserial=${join(root, 'serial.txt')}\nnew_certs_dir=${join(root, 'issued')}\ndefault_md=sha256\npolicy=policy\n[policy]\ncommonName=supplied\n[server]\nsubjectAltName=${hostname}\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature,keyEncipherment,keyCertSign,cRLSign\nextendedKeyUsage=serverAuth\n`)
  execFileSync('openssl', ['req', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', keyFile, '-out', requestFile, '-subj', '/CN=localhost'], { stdio: 'ignore' })
  execFileSync('openssl', ['ca', '-selfsign', '-batch', '-notext', '-rand_serial', '-config', configFile, '-keyfile', keyFile,
    '-in', requestFile, '-out', certFile, '-extensions', 'server', '-startdate', '20200101000000Z', '-enddate', '20991231235959Z'], { stdio: 'ignore' })
  return { keyFile, certFile }
}
