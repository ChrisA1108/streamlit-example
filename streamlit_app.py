import requests
import re
import json
import streamlit as st

def parse_hbom(hbom_json):
    results = []

    for components in hbom_json['components']:
        supplier = components.get('supplier', {}).get('name', '')
        if 'externalReferences' in components:
            for i in components['externalReferences']:
                referenceURL = i['url']
                description = components['description']

                cve_info = {
                    'supplier': supplier,
                    'description': description,
                    'referenceURL': referenceURL,
                    'cves': []
                }

                base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
                params = {'keywordSearch': f"{description}"}
                response = requests.get(base_url, params=params)

                if response.status_code == 200:
                    data = response.json()
                    if data.get('totalResults', 0) > 0:
                        cve_entries = data.get("vulnerabilities", [])
                        for entry in cve_entries:
                            cve_id = entry.get('cve', {}).get('id', "")
                            cve_descriptions = entry.get('cve', {}).get('descriptions', [])
                            cve_references = entry.get('cve', {}).get("references", [])

                            cve_data = {
                                'CVE': cve_id,
                                'references': cve_references,
                                'descriptions': cve_descriptions
                            }

                            cve_info['cves'].append(cve_data)

                results.append(cve_info)
        else:
            supplier_name = components.get('supplier', {}).get('name', "")
            description_base = components.get('description', "")
            no_reference_info = {
                'supplier': supplier_name,
                'description': description_base,
                'referenceURL': None,
                'cves': []
            }
            results.append(no_reference_info)

    return results

# Load the JSON data from the URL
HBOM = requests.get('https://raw.githubusercontent.com/ChrisA1108/Files/main/Zybo.json').json()

# Parse the HBOM and get the results
cve_results = parse_hbom(HBOM)

# Create a Streamlit app to display the results
st.title('HBOM CVE Analysis')
for cve_info in cve_results:
    st.header(f"{cve_info['supplier']}: {cve_info['description']}")
    if cve_info['referenceURL']:
        st.write(f'Reference URL: {cve_info["referenceURL"]}')
    for cve_data in cve_info['cves']:
        st.subheader(f'CVE: {cve_data["CVE"]}')
        for reference in cve_data['references']:
            st.write(f'References - Source: {reference.get("source", "")}, URL: {reference.get("url", "")}')
        for description in cve_data['descriptions']:
            st.write(f'CVE description in {description.get("lang", "")}: {description.get("value", "")}')
    st.write('---')
