from requests import auth, session, HTTPError
import sys
from os import environ as env
import subprocess

scan_profile_name = env.get('NS_PROFILE_NAME')
scan_website_id = env.get('NS_WEBSITE_ID')
ns_user = env.get('NS_USER')
ns_secret = env.get('NS_SECRET')
ci_run_id = env.get('CI_RUN_ID', '1')
auth0_client_id = env.get('auth0_client_id')
auth0_client_secret = env.get('auth0_client_secret')
auth0_audience = env.get('auth0_audience')
auth0_url = env.get('auth0_url', 'https://empirelife-dev.auth0.com/oauth/token')

ns_url = "https://www.netsparkercloud.com/api/1.0/"
ns_session = session()
ns_session.headers = {"Accept": "application/json", "Content-Type": "application/json"}
ns_session.auth = auth.HTTPBasicAuth(ns_user, ns_secret)

def cmd(s):
    p = subprocess.run(s.split(" "), stdout=subprocess.PIPE)
    return p.stdout.decode().strip()


def get_auth0_token(url, client_id, client_secret, audience):
    auth0_session = session()
    auth0_response = auth0_session.post(url, json={
        "client_id": client_id,
        "client_secret": client_secret,
        "audience": audience,
        "grant_type": "client_credentials"
    }, headers={"Accept": "application/json", "Content-Type": "application/json"})
    auth0_response.raise_for_status()
    return auth0_response.json().get('access_token')


def pullScanProfileJsonByName(profileName):
    sys.stdout.write("[API] Pulling Scan Profile..\n")
    response = ns_session.get(url=ns_url + "scanprofiles/get", params="name=%s&" % profileName)
    response.raise_for_status()
    return response.json()


def updateScanProfileJsonByName(scan_profile_json):
    sys.stdout.write("[API] Updating Scan Profile..\n")
    response = ns_session.post(url=ns_url + "scanprofiles/update", json=scan_profile_json)
    response.raise_for_status()
    return response.json()


def triggerScanWithProfile(scan_json):
    sys.stdout.write("[API] Launching new scan..\n")
    response = ns_session.post(url=ns_url + "scans/newwithprofile", json=scan_json)
    response.raise_for_status()
    return response.json()


git_author = cmd("git log -1 --pretty=format:%an")
git_hash = cmd("git rev-parse --verify --short HEAD")
git_url = cmd("git config --get remote.origin.url")

try:
    profile_json = pullScanProfileJsonByName(scan_profile_name)
    profile_json['HeaderAuthentication'] = {
        'IsEnabled': True,
        'Headers': [{
            'Name': 'Authorization',
            'Value': 'Bearer ' + get_auth0_token(auth0_url, auth0_client_id, auth0_client_secret, auth0_audience)
        }]
    }
    print(profile_json)

    update_resp = updateScanProfileJsonByName(profile_json)
    print(update_resp)

    scan_json = {
        'TargetUri': profile_json['TargetUri'],
        'ProfileId': profile_json['ProfileId'],
        'ProfileName': profile_json['ProfileName'],
        'WebsiteId': scan_website_id,
        'ScanType': 'Full',
        'VcsCommitInfoModel': {
            'CiBuildConfigurationName': git_url,
            'CiBuildHasChange': True,
            'CiBuildId': ci_run_id,
            'Committer': git_author,
            'VcsName': 'git',
            'VcsVersion': git_hash
        }
    }
    triggerScanWithProfile(scan_json)

except HTTPError as e:
    raise Exception(str(e.response.content))
