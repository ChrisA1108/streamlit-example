import requests
import re
import time
import os
import base64
import json
from typing import Dict
import streamlit as st

# Global variables to store CVE information
global_cve_data = []
cve_found = False
alternative_parts_searched = False

NEXAR_URL = "https://api.nexar.com/graphql"
PROD_TOKEN_URL = "https://identity.nexar.com/connect/token"

QUERY_MPN = '''
query Search($mpn: String!) {
    supSearchMpn(q: $mpn, limit: 1) {
    hits
      results {
        part {
          similarParts {
              name
              mpn
              bestDatasheet{
              url
              }
          }
        }
      }
    }
}
'''

def get_token(client_id, client_secret):
    if not client_id or not client_secret:
        raise Exception("client_id and/or client_secret are empty")

    token = {}
    try:
        token = requests.post(
            url=PROD_TOKEN_URL,
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret
            },
            allow_redirects=False,
        ).json()

    except Exception:
        raise

    return token

def decode_jwt(token):
    return json.loads(
        (base64.urlsafe_b64decode(token.split(".")[1] + "==")).decode("utf-8")
    )

class NexarClient:
    def __init__(self, id, secret) -> None:
        self.id = id
        self.secret = secret
        self.s = requests.session()
        self.s.keep_alive = False

        self.token = get_token(id, secret)
        self.s.headers.update({"token": self.token.get('access_token')})
        self.exp = decode_jwt(self.token.get('access_token')).get('exp')

    def check_exp(self):
        if self.exp < time.time() + 300:
            self.token = get_token(self.id, self.secret)
            self.s.headers.update({"token": self.token.get('access_token')})
            self.exp = decode_jwt(self.token.get('access_token')).get('exp')

    def get_query(self, query: str, variables: Dict) -> dict:
        try:
            self.check_exp()
            r = self.s.post(
                NEXAR_URL,
                json={"query": query, "variables": variables},
            )

        except Exception as e:
            print(e)
            raise Exception("Error while getting Nexar response")

        response = r.json()
        if "errors" in response:
            for error in response["errors"]:
                print(error["message"])
            raise SystemExit

        return response["data"]



os.environ['NEXAR_CLIENT_ID'] = '29d658fb-db21-4b9f-a017-3628569eb25f'
os.environ['NEXAR_CLIENT_SECRET'] = 'bd8IoOy-5S13Hy2oSd9PuVnCKUCFjgM_YTiN'

client_id = os.environ['NEXAR_CLIENT_ID']
client_secret = os.environ['NEXAR_CLIENT_SECRET']
nexar_client = NexarClient(client_id, client_secret)


# cve lookup function
def cve_lookup(searchByKeyword, keyword, supplier):
    global global_cve_data, cve_found
    cve_found = False
    global_cve_data = []

    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    if searchByKeyword:
        # Search by keyword in the description of CVE
        params = {'keywordSearch': f"{keyword}"}

    else:
        supplier_name = supplier.split(" ")
        params = {'cpeName': f"cpe:2.3:h:{supplier_name[0]}:{keyword}:-:*:*:*:*:*:*:*"}

    apiKey = {'apiKey': 'e4b22778-a67d-4996-b3ff-ad31ead6d73d'}
    response = requests.get(base_url, params=params, headers=apiKey)

    if response.status_code == 200:
        data = response.json()
        totalResults = data.get('totalResults', 0)
        if 0 < totalResults < 10:
            keywordValid = True
            cve_entries = data.get("vulnerabilities", {})

            for entry in cve_entries:
                cve_id = entry.get('cve', {}).get('id', "")
                cve_descriptions = entry.get('cve', {}).get('descriptions', {})
                cve_weaknesses = entry.get('cve', {}).get('weaknesses', {})
                cve_references = entry.get('cve', {}).get("references", {})

                if searchByKeyword:
                    # get cve description
                    description_textEng = cve_descriptions[0].get('value')
                    # Create a regular expression pattern that matches the keyword as a whole word
                    for _ in keyword.split(" "):
                        pattern = re.compile(r'\b' + re.escape(_) + r'\b', re.IGNORECASE)

                        # Check if the keyword appears as a whole word in the description
                        if not re.search(pattern, description_textEng):
                            keywordValid = False

                if keywordValid:
                    cve_found = True  # Set the flag to True
                    if cve_id and cve_descriptions:
                        # get cve metrics
                        if entry.get('cve', {}).get('metrics', {}).get('cvssMetricV31', {}):
                            cve_cvss = entry.get('cve', {}).get('metrics', {}).get('cvssMetricV31', {})[0]
                            cve_metrics = cve_cvss.get('cvssData', {})
                            exploitScore = cve_cvss['exploitabilityScore']
                            impactScore = cve_cvss['impactScore']
                            integrity_Impact = cve_metrics['integrityImpact']
                            confidentiality_Impact = cve_metrics['confidentialityImpact']
                            availability_Impact = cve_metrics['availabilityImpact']
                            attack_vector = cve_metrics['attackVector']

                        for reference in cve_references:
                            reference_url = reference.get("url", "")
                            reference_source = reference.get("source", "")

                        cve_text = []
                        for description in cve_descriptions:
                            cve_text.append(description.get('value', ""))
                            description_lang = description.get('lang', "")

                    if cve_weaknesses:
                        cwe_names = []
                        for cve_cwe in cve_weaknesses:
                            cwe_source = cve_cwe.get('source', "")
                            cwe_description = cve_cwe.get('description', {})
                            if cwe_description:
                                for cwe in cwe_description:
                                    cwe_name = cwe.get('value', "")
                                    cwe_names.append(cwe_name)

                    # store the CVE information in global_cve_data
                    global_cve_data.append({
                        'cveId': cve_id,
                        'supplier': supplier,
                        'cveDescription': cve_text,
                        'referenceURL': reference_url,
                        'cweName': cwe_names,
                        'exploitScore': exploitScore,
                        'impactScore': impactScore,
                        'integrity_Impact': integrity_Impact,
                        'confidentiality_Impact': confidentiality_Impact,
                        'availability_Impact': availability_Impact,
                        'attack_vector': attack_vector,
                        # Add other relevant information as needed
                    })
    time.sleep(0.6)

def process_hbom(HBOM):
    global cve_found, alternative_parts_searched, nexar_client
    alternative_parts = False
    for components in HBOM['components']:
        searchByKeyword = True  # start by search
        cve_found = False # Flag to check if CVEs were found
        keyCnt = 0  # keep track of what keyword
        cve_name = components.get('name')

        supplier = components.get('supplier', {}).get('name', '')
        description = components['description']
        st.write(f'# {supplier}: {description}')
        if 'externalReferences' in components:
            for i in components['externalReferences']:
                referenceURL = i['url']
            st.write(f'referenceURL: {referenceURL}')

        keyDesc = components['description'].split(" ")
        keywords = components['name'].split('-')
        keywords.insert(0, components['description'])

        if isinstance(keyDesc, list):
            for i in range(len(keyDesc), 1, -1):
                sub_list = keyDesc[:i]
                joined_string = ' '.join(sub_list)
                keywords.append(joined_string)
        else:
            keywords.append(keyDesc)

        keyDesc = components['description'].replace(' ', '_')

        originalCnt = len(keywords)
        keywords.append(keyDesc)

        for keyword in keywords:

            if originalCnt == keyCnt:
                searchByKeyword = False

            keyCnt += 1

            if keyword.lower() == supplier.lower():
                continue

            if searchByKeyword:
                cve_lookup(searchByKeyword, keyword, supplier)
            else:
                cve_lookup(searchByKeyword, keyword, supplier)

            if cve_found:
                break

        # return CVE details
        if cve_found:
            # Access global_cve_data after processing
            for cve_entry in global_cve_data:
                # Print cve name
                st.write(f"CVE: {cve_entry['cveId']}")
                # Print cve description
                st.write(f"CVE Description: {cve_entry['cveDescription'][0]}")
                # Print cvw
                for cwe in cve_entry['cweName']:
                    st.write(f"CWE: {cwe}")

            variables = {'mpn': cve_name}
            results = nexar_client.get_query(QUERY_MPN, variables)

            if results:
                results_num = results.get("supSearchMpn", {}).get("hits", 0)
                if results_num > 0:
                    st.write(" \tAlternative Parts")
                    alternative_parts_searched = True
                    for it in results.get("supSearchMpn", {}).get("results", {}):
                        alternative_parts = it.get("part", {}).get("similarParts", {})
                        for part in alternative_parts:
                            part_name = part.get("name")
                            part_mpn = part.get('mpn')
                            st.write(f" \tAlternative Part Suggestion: {part_name}")
                            if part.get('bestDatasheet', {}):
                                datasheet_url = part.get("bestDatasheet").get('url')
                                st.write(f" \tPart DataSheet: {datasheet_url}")

                            # search alternative parts for cve's
                            # sarching by keyword so no need for supplier
                            cve_lookup(True, part_mpn, "")
                            if cve_found:
                                for cve_entry in global_cve_data:
                                    # Print cve name
                                    st.write(f" \t\ttCVE: {cve_entry['cveId']}")
                                    # Print cve description
                                    st.write(f" \t\tCVE Description: {cve_entry['cveDescription'][0]}")
                                    # Print cvw
                                    for cwe in cve_entry['cweName']:
                                        st.write(f" \t\tCWE: {cwe}")
                            else:
                                st.write(f" \t\tNo CVE's Found for part {part_name}")
                                st.write("")

                else:
                    st.write("\tNo Alternative Parts Found")
                    st.write("")

        if not cve_found and not searchByKeyword:
            st.write("NO CVEs FOUND")
            st.write()
            
st.title("HBOM Component Processing")

# Allow users to upload a JSON file
uploaded_file = st.file_uploader("Upload a JSON file", type=["json"])

if uploaded_file:
    # Read the uploaded JSON file
    hbom_json = uploaded_file.read()
    hbom_data = json.loads(hbom_json)

    # Process and display the data using the Streamlit app
    process_hbom(hbom_data)
