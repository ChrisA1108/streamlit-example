import requests
import re
import streamlit as st

def parse_hbom(hbom_json):
    results = []
    for components in hbom_json['components']:
        supplier = components.get('supplier', {}).get('name', '')
        if 'externalReferences' in components:
            for i in components['externalReferences']:
                referenceURL = i['url']
                description = components['description']
                result = {
                    'Supplier': supplier,
                    'Description': description,
                    'ReferenceURL': referenceURL,
                    'CVEs': []
                }
                base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
                params = {'keywordSearch': f"{description}"}
                response = requests.get(base_url, params=params)
                if response.status_code == 200:
                    data = response.json()
                    if data.get('totalResults', 0) > 0:
                        cve_entries = data.get("vulnerabilities", {})
                        for entry in cve_entries:
                            cve_id = entry.get('cve', {}).get('id', "")
                            cve_descriptions = entry.get('cve', {}).get('descriptions', {})
                            cve_references = entry.get('cve', {}).get("references", {})
                            cve_info = {
                                'CVE': cve_id,
                                'References': [{'Source': ref.get("source", ""), 'URL': ref.get("url", "")}
                                               for ref in cve_references],
                                'Descriptions': [{'Lang': desc.get('lang', ""), 'Value': desc.get('value', "")}
                                                for desc in cve_descriptions]
                            }
                            result['CVEs'].append(cve_info)
                results.append(result)
        else:
            supplier_name = components.get('supplier', {}).get('name', "")
            description_base = components.get('description', "")
            result = {
                'Supplier': supplier_name,
                'Description': description_base,
                'ReferenceURL': None,
                'CVEs': []
            }
            results.append(result)
    return results

st.title("HBOM Parser")

HBOM = requests.get('https://raw.githubusercontent.com/ChrisA1108/Files/main/Zybo.json').json()

parsed_data = parse_hbom(HBOM)

for entry in parsed_data:
    st.subheader(f'{entry["Supplier"]}: {entry["Description"]}')
    if entry["ReferenceURL"]:
        st.write(f'Reference URL: {entry["ReferenceURL"]}')
    for cve in entry["CVEs"]:
        st.write(f'CVE: {cve["CVE"]}')
        for reference in cve["References"]:
            st.write(f'Reference - Source: {reference["Source"]}, URL: {reference["URL"]}')
        for description in cve["Descriptions"]:
            st.write(f'CVE description in {description["Lang"]}: {description["Value"]}')
    st.write("")

st.write()
