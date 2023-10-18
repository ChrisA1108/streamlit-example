import streamlit as st
import requests
import re
import json

def process_hbom(hbom_json):
    for components in hbom_json['components']:
        supplier = components.get('supplier', {}).get('name', '')

        if 'externalReferences' in components:
            cves_found = False  # Track if any CVEs were found for this component
            # Check if the component has external references
            for i in components['externalReferences']:
                referenceURL = i['url']
                description = components['description']

                # Print supplier and description
                st.write(f'{supplier}: {description}')
                st.write(f'referenceURL: {referenceURL}')
                st.write('')

                # Define the base URL for querying vulnerabilities
                base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

                # Prepare the search parameters using the component description
                params = {'keywordSearch': f"{description}"}
                response = requests.get(base_url, params=params)

                if response.status_code == 200:
                    data = response.json()

                    if data.get('totalResults', '') > 0:
                        cves_found = True  # CVEs found for this component
                        cve_entries = data.get("vulnerabilities", {})

                        for entry in cve_entries:
                            cve_id = entry.get('cve', {}).get('id', "")
                            cve_descriptions = entry.get('cve', {}).get('descriptions', {})
                            cve_weaknesses = entry.get('cve', {}).get('weaknesses', {})
                            cve_references = entry.get('cve', {}).get("references", {})

                            cpe_string = entry.get('cve', {}).get("configurations", {})[0].get('nodes', {})[0].get('cpeMatch', {})[0].get('criteria', "")
                            pattern = r'(.*?):(.*?):(.*?):' + re.escape(supplier.lower()) + r':'

                            # Use regular expressions to find a match in the CPE string
                            if re.findall(pattern, cpe_string):
                                if cve_id and cve_descriptions:
                                    # Print CVE details
                                    st.write(f'CVE: {cve_id}')

                                    for reference in cve_references:
                                        reference_url = reference.get("url", "")
                                        reference_source = reference.get("source", "")
                                        st.write(f'References - Source: {reference_source}, URL: {reference_url}')

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
                                st.write('')

            if not cves_found:
                st.write("No current CVEs for this component")
        else:
            supplier_name = components.get('supplier', {}).get('name', "")
            description_base = components.get('description', "")

            # Print supplier and description if there are no external references
            st.write(f'{supplier_name}: {description_base}')

st.title("HBOM Component Processing")

# Allow users to upload a JSON file
uploaded_file = st.file_uploader("Upload a JSON file", type=["json"])

if uploaded_file:
    # Read the uploaded JSON file
    hbom_json = uploaded_file.read()
    hbom_data = json.loads(hbom_json)

    # Process and display the data using the Streamlit app
    process_hbom(hbom_data)
