import requests
import re
import time
import streamlit as st
import json

def process_hbom(json_data):
    for components in json_data['components']:
        keyCnt = 0 # count for keeping track of keys
        cve_found = False  # Flag to check if CVEs were found
        searchByKeyword = True
        supplier = components.get('supplier', {}).get('name', '')
        description = components['description']

        # Print supplier and description
        st.write(f'# {supplier}: {description}')
        if 'externalReferences' in components:
            # Check if the component has external references
            for i in components['externalReferences']:
                referenceURL = i['url']

            st.write(f'referenceURL: {referenceURL}')

        keyDesc = components['description'].split(" ")
        keywords = components['name'].split('-')

        # check if keyDesc is a list or not for appending to keywords
        if isinstance(keyDesc, list):
            keywords = keywords + keyDesc
        else:
            print("not")

        keyDesc = components['description'].replace(' ', '_')
        # Define the base URL for querying vulnerabilities
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

        # go through each keyword to search for possible CVE's
        for keyword in keywords:
            # keep track of which keywords are for what purpose
            if originalCnt == keyCnt:
                searchByKeyword = False
            keyCnt += 1

            if keyword.lower() == supplier.lower():
                # Skip keyword search when it's the same as the supplier
                continue

            # If no CVEs were found for any keyword, you can use different parameters for requests and keywords
            if searchByKeyword:
                # Search by keyword in the description of CVE
                params = {'keywordSearch': f"{keyword}"}

            else:
                # search by vendor and component name
                supplier_name = supplier.split(" ")
                params = {'cpeName': f"cpe:2.3:h:{supplier_name[0]}:{keyword}:-:*:*:*:*:*:*:*"}

            time.sleep(1)
            response = requests.get(base_url, params=params)

            if response.status_code == 200:
                data = response.json()
                totalResults = data.get('totalResults', 0)
                if 0 < totalResults < 10:
                    
                    cve_found = True  # Set the flag to True
                    keywordValid = True
                    st.write("")
                    cve_entries = data.get("vulnerabilities", {})

                    # go through each cve found 
                    for entry in cve_entries:
                        cve_id = entry.get('cve', {}).get('id', "")
                        cve_descriptions = entry.get('cve', {}).get('descriptions', {})
                        cve_weaknesses = entry.get('cve', {}).get('weaknesses', {})
                        cve_references = entry.get('cve', {}).get("references", {})
                        if entry.get('cve', {}).get('metrics', {}).get('cvssMetricV31', {}):
                            cve_cvss = entry.get('cve', {}).get('metrics', {}).get('cvssMetricV31', {})[0]
                            exploitScore = cve_cvss['exploitabilityScore']
                            impactScore = cve_cvss['impactScore']

                            cve_scores = f'Exploitability Score: {exploitScore}  Impact Score: {impactScore}'

                        if searchByKeyword:
                            # Create a regular expression pattern that matches the keyword as a whole word
                            pattern = re.compile(r'\b' + re.escape(keyword) + r'\b', re.IGNORECASE)
                            # get cve description
                            description_textEng = cve_descriptions[0].get('value')
                            if not re.search(pattern, description_textEng):
                                keywordValid = False

                        if keywordValid:
                            if cve_id and cve_descriptions:
                                # Print CVE details
                                st.write(f'CVE: {cve_id}')

                                st.write(f'nvd@nist.gov CVE Scores: {cve_scores}')

                                # Print all references for all CVEs
                                for reference in cve_references:
                                    reference_url = reference.get("url", "")
                                    reference_source = reference.get("source", "")
                                    st.write(f'References - Source: {reference_source}, URL: {reference_url}')

                                # Print CVE descriptions in languages available
                                for description in cve_descriptions:
                                    description_text = description.get('value', "")
                                    description_lang = description.get('lang', "")
                                    st.write(f'CVE description in {description_lang}: {description_text}')
                            elif cve_id and not cve_descriptions:
                                # Print CVE without descriptions
                                st.write(f'CVE: {cve_id}')

                            if cve_weaknesses:
                                for cve_cwe in cve_weaknesses:
                                    cwe_source = cve_cwe.get('source', "")
                                    cwe_description = cve_cwe.get('description', {})
                                    if cwe_description:
                                        for cwe in cwe_description:
                                            cwe_name = cwe.get('value', "")
                                            # Print CWE information
                                            st.write(f'CWE for {cve_id}: {cwe_name}, Source: {cwe_source}')

                    st.write("")

            if cve_found:
                break  # Exit the loop as soon as CVEs are found

        if cve_found:
            # If CVEs were found, you can continue with other components
            continue
            
        if not cve_found and not searchByKeyword:
            st.write("### NO CVEs FOUND")
            st.write("")
            
st.title("HBOM Component Processing")

# Allow users to upload a JSON file
uploaded_file = st.file_uploader("Upload a JSON file", type=["json"])

if uploaded_file:
    # Read the uploaded JSON file
    hbom_json = uploaded_file.read()
    hbom_data = json.loads(hbom_json)

    # Process and display the data using the Streamlit app
    process_hbom(hbom_data)
