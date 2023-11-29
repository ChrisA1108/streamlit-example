import requests
import re
import time
import streamlit as st
import json

# Global variables to store CVE information
global_cve_data = []
cve_found = False

def cve_lookup(searchByKeyword, keyword, supplier):
    global global_cve_data, cve_found

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
            cve_found = True  # Set the flag to True
            keywordValid = True
            cve_entries = data.get("vulnerabilities", {})

            for entry in cve_entries:
                cve_id = entry.get('cve', {}).get('id', "")
                cve_descriptions = entry.get('cve', {}).get('descriptions', {})
                cve_weaknesses = entry.get('cve', {}).get('weaknesses', {})
                cve_references = entry.get('cve', {}).get("references", {})

                if searchByKeyword:
                    # Create a regular expression pattern that matches the keyword as a whole word
                    pattern = re.compile(r'\b' + re.escape(keyword) + r'\b', re.IGNORECASE)
                    # get cve description
                    description_textEng = cve_descriptions[0].get('value')
                    if not re.search(pattern, description_textEng):
                        keywordValid = False

                if keywordValid:
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
    time.sleep(0.8)

def process_hbom(HBOM):
    global cve_found
    for components in HBOM['components']:
        searchByKeyword = True  # start by search
        cve_found = False # Flag to check if CVEs were found
        keyCnt = 0  # keep track of what keyword

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
            keywords = keywords + keyDesc
        else:
            keywords.append(keyDesc)

        keyDesc = components['description'].replace(' ', '_')

        originalCnt = len(keywords)
        keywords.append(keyDesc)

        for keyword in keywords:
            #print("loop")
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

                st.write(f"Exploit Score {cve_entry['exploitScore']}")

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
