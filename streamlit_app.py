import requests
import re
import streamlit as st

st.title("Component Data Sheet and CVE Information")

# Load the JSON data from the provided URL
HBOM = requests.get('https://raw.githubusercontent.com/ChrisA1108/Files/main/Zybo.json').json()

for components in HBOM['components']:
    supplier = components.get('supplier', {}).get('name', '')

    if 'externalReferences' in components:
        # Check if the component has external references
        for i in components['externalReferences']:
            referenceURL = i['url']
            description = components['description']

            # Display supplier and description
            st.write(f'{supplier}: {description}')
            st.write(f'referenceURL: {referenceURL}')
            st.write()

            # Define the base URL for querying vulnerabilities
            base_url = "https://services.nvd.nist.gov/rest/json/cves/1.0"

            # Prepare the search parameters using the component description
            params = {'keywordSearch': f"{description}"}
            response = requests.get(base_url, params=params)

            if response.status_code == 200:
                data = response.json()

                if data.get('totalResults', 0) > 0:
                    cve_entries = data.get("result", {}).get("CVE_Items", [])

                    for entry in cve_entries:
                        cve_id = entry.get('cve', {}).get('CVE_data_meta', {}).get('ID', "")
                        cve_descriptions = entry.get('cve', {}).get('description', {}).get('description_data', [])
                        cve_references = entry.get('cve', {}).get("references", {}).get("reference_data", [])

                        cpe_string = entry.get('configurations', {}).get('nodes', [])[0].get('cpe_match', [])[0].get('cpe_string', "")
                        pattern = r'(.*?):(.*?):(.*?):' + re.escape(supplier.lower()) + r':'

                        # Use regular expressions to find a match in the CPE string
                        if re.findall(pattern, cpe_string):
                            if cve_id and cve_descriptions:
                                # Display CVE details
                                st.write(f'CVE: {cve_id}')

                                for reference in cve_references:
                                    reference_url = reference.get("url", "")
                                    reference_source = reference.get("source_name", "")
                                    st.write(f'References - Source: {reference_source}, URL: {reference_url}')

                                for description in cve_descriptions:
                                    description_text = description.get('value', "")
                                    st.write(f'CVE description: {description_text}')
                            elif cve_id and not cve_descriptions:
                                # Display CVE without descriptions
                                st.write(f'CVE: {cve_id}')

    else:
        supplier_name = components.get('supplier', {}).get('name', "")
        description_base = components.get('description', "")

        # Display supplier and description if there are no external references
        st.write(f'{supplier_name}: {description_base}')

