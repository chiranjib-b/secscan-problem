import requests
import sys
import json
import urllib

session = requests.Session()
session.auth = ('chiranjib_b','c1NF4rentyL3DbSt32khks6iLol4CHMRK7OT8t9e10sIf493wI7oR78j/h+tKyjG')
input_file = sys.argv[1]

with open(input_file,'r') as inp:
    cont = inp.read()
    inp = json.loads(cont)

ret = []

tag_url = 'https://quay.io/api/v1/repository/{0}/{1}/tag/?specificTag={2}'
secscan_url = 'https://quay.io/api/v1/repository/{0}/{1}/manifest/{2}/security?vulnerabilities=true'

for repo_obj in inp:
    org = repo_obj['Organisation']
    repo = repo_obj['Repository']
    tag = repo_obj['Tag']
    url = tag_url.format(org, repo, tag)
    print('Fetching ' + url)
    output = session.get(url)
    if output.status_code == 200:
        resp = output.json()
        if not resp['tags']:
            print('No information found for repo and tag combination')
        else:
            for entry in resp['tags']:
                org_obj = {
                    'Organisation': org,
                    'Repository' : repo,
                    'Tag': tag,
                    'Manifest' : entry['manifest_digest']
                }
                manifest = urllib.parse.quote(entry['manifest_digest'])
                secscan_resp = session.get(secscan_url.format(org, repo, manifest))
                secscan_resp = secscan_resp.json()
                if secscan_resp['status'] == 'scanned':
                    for app_entry in secscan_resp['data']['Layer']['Features']:
                        if 'Vulnerabilities' in app_entry:
                            org_obj['Vulnerabilities'] = app_entry['Vulnerabilities']
                            ret.append(org_obj)
                else:
                    print('Manifest {0} of {1}/{2} is not yet scanned.'.format(entry['manifest_digest'], org, repo))
    else:
        print('Request {0} failed with code: {1}'.format(url, output.status_code))

print('Vulnerabilities found:\n{0}'.format(ret))

session.close()