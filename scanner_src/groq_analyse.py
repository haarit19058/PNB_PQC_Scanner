import os
import json
import pandas as pd
from groq import Groq
from dotenv import load_dotenv

load_dotenv()

# 1. Initialize Groq Client
client = Groq(api_key=os.environ.get("GROQ_API_KEY"))
MODEL_NAME = "llama-3.3-70b-versatile"

# 2. Load your new streamlined Batch CBOM data
data = pd.read_csv('Batch_CBOM.csv')
analysis_results = []

print("Analyzing domains for Post-Quantum Cryptography (PQC) readiness...\n")

# 3. Iterate through each domain (now 1 row per domain)
for index, row in data.iterrows():
    domain_url = row.get('Hostname', 'Unknown Host')
    print(f"Analyzing: {domain_url}...")

    # Handle domains that failed both PQC and Classical scans
    if row.get('Scan_Status') == 'Failed':
         analysis_results.append({
             "Hostname": domain_url,
             "Is_PQC_Safe": "No",
             "Rectification_Steps": f"Server is unreachable or completely misconfigured. Error: {row.get('Error_Details')}."
         })
         continue

    row_data_str = row.to_json()

    # ==========================================
    # 4. THE PROMPT (Adapted for Waterfall Data)
    # ==========================================
    prompt = f"""
    You are an expert Post-Quantum Cryptography (PQC) security analyst. I am providing you with a Cryptography Bill of Materials (CBOM) for a specific domain.
    
    CRITICAL CONTEXT FOR YOUR ANALYSIS:
    1. Look at the "Scan_Type" field in the JSON. 
       - If Scan_Type is "PQC Probe", the server successfully negotiated a PQC Hybrid Key Exchange (like X25519MLKEM768). It IS "PQC Safe".
       - If Scan_Type is "Classical Fallback", the server rejected the PQC connection and only supports legacy cryptography. It is NOT "PQC Safe".
    2. Do NOT penalize a domain for using an RSA or ECDSA certificate if the Scan_Type is "PQC Probe". Hybrid architecture (Classical Cert + PQC Key Exchange) is the current industry standard for PQC readiness.

    Here is the CBOM data:
    {row_data_str}

    Provide your analysis STRICTLY in the following JSON format. Do not include markdown formatting or preamble.

    {{
        "Hostname": "{domain_url}",
        "Is_PQC_Safe": "Yes" or "No",
        "Rectification_Steps": "Provide concise, actionable advice. If it is a Classical Fallback, tell them to upgrade their TLS termination to support hybrid KEMs. If it is already PQC Safe, tell them to monitor for future ML-DSA certificate support."
    }}
    """

    try:
        response = client.chat.completions.create(
            messages=[
                {"role": "system", "content": "You are a strict JSON-only API that evaluates cryptographic assets for post-quantum safety."},
                {"role": "user", "content": prompt}
            ],
            model=MODEL_NAME,
            temperature=0.0, 
            response_format={"type": "json_object"} 
        )

        result_dict = json.loads(response.choices[0].message.content)
        analysis_results.append(result_dict)

    except Exception as e:
        print(f"Error analyzing {domain_url}: {e}")
        analysis_results.append({
            "Hostname": domain_url,
            "Is_PQC_Safe": "Error",
            "Rectification_Steps": f"LLM Error: {str(e)}"
        })

# ==========================================
# 5. EXPORT AND MERGE
# ==========================================
df_llm = pd.DataFrame(analysis_results)

# Optional: Merge the LLM advice back into your main CSV so it's all in one place
df_master = pd.merge(data, df_llm, on="Hostname", how="left")
df_master.to_csv("Master_PQC_Report.csv", index=False)

print("\nAnalysis complete! Data saved to Master_PQC_Report.csv")

pd.set_option('display.max_columns', None)
print("\nPreview:")
print(df_master[["Hostname", "Scan_Type", "Is_PQC_Safe", "Rectification_Steps"]].head())
df_master.to_csv('new_scanner.csv')