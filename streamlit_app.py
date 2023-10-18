import streamlit as st
import requests
import re
import json

# Function to parse HBO Max JSON
def parse_hbom(hbom_json):
    result = []

    for components in hbom_json['components']:
        supplier = components.get('supplier', {}).get('name', '')
        entry = {
            'supplier': supplier,
            'description': components.get('description', ''),
            'referenceURL': None,
            'cve_entries': []  # Initialize an empty list for CVE entries
        }

        if 'externalReferences' in components:
            for i in components['externalReferences']:
                entry['referenceURL'] = i['url']

                base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
                params = {'keywordSearch': entry['description']}
                response = requests.get(base_url, params=params)

                if response.status_code == 200:
                    data = response.json()
                    if data.get('totalResults', 0) > 0:
                        cve_entries = data.get("vulnerabilities", {})
                        for cve_entry in cve_entries:
                            cve_id = cve_entry.get('cve', {}).get('id', "")
                            cve_descriptions = cve_entry.get('cve', {}).get('descriptions', {})
                            cve_references = cve_entry.get('cve', {}).get("references", {})
                            cve_weaknesses = cve_entry.get('cve', {}).get('weaknesses', {})

                            cpe_string = cve_entry.get('cve', {}).get("configurations", {})[0].get('nodes', {})[0].get(
                                'cpeMatch', {})[0].get('criteria', "")
                            pattern = r'(.*?):(.*?):(.*?):' + re.escape(supplier.lower()) + r':'

                            if re.findall(pattern, cpe_string):
                                cve_info = {
                                    'CVE': cve_id,
                                    'References': [],
                                    'Descriptions': []
                                }

                                for reference in cve_references:
                                    reference_url = reference.get("url", "")
                                    reference_source = reference.get("source", "")
                                    cve_info['References'].append({
                                        'Source': reference_source,
                                        'URL': reference_url
                                    })

                                for description in cve_descriptions:
                                    description_text = description.get('value', "")
                                    description_lang = description.get('lang', "")
                                    cve_info['Descriptions'].append({
                                        'Language': description_lang,
                                        'Description': description_text
                                    })

                                entry['cve_entries'].append(cve_info)  # Append CVE info to the entry
        result.append(entry)

    return result

# Streamlit app
st.title("HBO Max JSON Parser")

uploaded_file = st.file_uploader("Upload your HBO Max JSON file", type=["json"])

if uploaded_file is not None:
    try:
        hbom_json = json.load(uploaded_file)
        parsed_data = parse_hbom(hbom_json)
        st.write("Parsed Data:")
        st.write(parsed_data)
    except json.JSONDecodeError:
        st.error("Invalid JSON file. Please upload a valid JSON file.")
