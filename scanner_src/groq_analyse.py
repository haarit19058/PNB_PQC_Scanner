import os
import json
import pandas as pd
from groq import Groq
from dotenv import load_dotenv

load_dotenv()

# 1. Initialize Groq Client
# Ensure you have your API key set as an environment variable: GROQ_API_KEY
client = Groq(api_key=os.environ.get("GROQ_API_KEY"))

# Select a fast and capable model from Groq (e.g., Llama 3 70B)
MODEL_NAME = "llama-3.3-70b-versatile"

# 2. Load your generated Batch CBOM data
# Make sure the filename matches what you saved in the previous step
data = pd.read_csv('Batch_CBOM.csv')

# List to store the structured results
analysis_results = []

print("Analyzing domains for Post-Quantum Cryptography (PQC) readiness...\n")

# 3. Iterate through each domain's CBOM data
for index, row in data.iterrows():
    domain_url = row.get('Domain (URL)', 'Unknown URL')
    
    # Skip rows that failed the initial scan
    if row.get('Scan_Status') == 'Failed':
        print(f"Skipping {domain_url} (Failed initial scan)")
        analysis_results.append({
            "URL": domain_url,
            "Is_PQC_Safe": "Unknown",
            "Rectification_Steps": "Cannot analyze; initial TLS scan failed."
        })
        continue

    print(f"Analyzing: {domain_url}...")

    # Convert the row to a dictionary/string to feed into the prompt
    row_data_str = row.to_json()

    # ==========================================
    # 4. THE PROMPT
    # ==========================================
    prompt = f"""
    You are an expert cryptography security analyst. I am providing you with a Cryptography Bill of Materials (CBOM) for a specific domain. 
    
    Your task is to determine if this domain's cryptographic assets (Keys, Algorithms, Protocols) are Post-Quantum Cryptography (PQC) safe. 
    *Note: Standard RSA, DSA, and ECC (Elliptic Curve) are vulnerable to Shor's algorithm and are NOT PQC safe. Only algorithms like ML-KEM (Kyber), ML-DSA (Dilithium), SLH-DSA (SPHINCS+), or hybrid implementations are PQC safe.*

    Here is the CBOM data for the domain:
    {row_data_str}

    Provide your analysis STRICTLY in the following JSON format. Do not include any markdown formatting, preamble, or trailing text. Just the raw JSON object.

    {{
        "URL": "{domain_url}",
        "Is_PQC_Safe": "Yes" or "No",
        "Rectification_Steps": "Provide a concise, comma-separated list or short paragraph of the exact steps needed to migrate this specific asset to a PQC-safe standard (e.g., migrate from RSA-2048 to a hybrid Kyber-RSA TLS certificate)."
    }}
    """

    # 5. Send to Groq
    try:
        response = client.chat.completions.create(
            messages=[
                {
                    "role": "system",
                    "content": "You are a strict JSON-only API that evaluates cryptographic assets for post-quantum safety."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            model=MODEL_NAME,
            temperature=0.1, # Low temperature for highly deterministic, consistent output
            response_format={"type": "json_object"} # Forces Groq to return valid JSON
        )

        # Extract the JSON string from the response
        llm_output = response.choices[0].message.content
        
        # Parse the JSON string into a Python dictionary
        result_dict = json.loads(llm_output)
        
        # Append to our results list
        analysis_results.append(result_dict)

    except Exception as e:
        print(f"Error analyzing {domain_url}: {e}")
        analysis_results.append({
            "URL": domain_url,
            "Is_PQC_Safe": "Error",
            "Rectification_Steps": f"Failed to get response from LLM: {str(e)}"
        })

# ==========================================
# 6. EXPORT TO NEW DATAFRAME
# ==========================================
# Convert the list of JSON responses back into a structured DataFrame
df_pqc_analysis = pd.DataFrame(analysis_results)

# Save to a new CSV
output_filename = "PQC_Readiness_Report.csv"
df_pqc_analysis.to_csv(output_filename, index=False)

print(f"\nAnalysis complete! Data saved to {output_filename}")

# Preview the results
pd.set_option('display.max_columns', None)
pd.set_option('display.max_colwidth', None) # Don't truncate the steps
print("\nPreview:")
print(df_pqc_analysis.head())