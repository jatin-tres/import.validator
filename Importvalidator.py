import streamlit as st
import pandas as pd
import io
import re

# Set page configuration
st.set_page_config(page_title="TRES Import Validator", layout="wide")

def validate_csv(df):
    """
    Validates the dataframe based on TRES Import Template rules.
    Returns:
        - annotated_df: DataFrame with an added 'Validation Errors' column.
        - error_count: Total number of errors found.
    """
    # Create a copy to avoid modifying the original until ready
    annotated_df = df.copy()
    annotated_df['Validation Errors'] = ""
    
    # 1. Define Expected Columns
    expected_columns = [
        "Year", "Month", "Day", "Time", "Organizational Wallet", "Participating Wallet",
        "Network", "Direction", "Financial Action", "Asset Identifier", "Amount",
        "Fiat Value (optional)", "Fiat Currency", "Transaction Hash", "Transfer ID",
        "Function Name", "Method ID"
    ]
    
    # Check for missing columns
    missing_cols = [col for col in expected_columns if col not in df.columns]
    if missing_cols:
        st.error(f"Missing required columns: {', '.join(missing_cols)}")
        return None, len(missing_cols)

    # 2. Row-by-Row Validation
    errors_dict = {i: [] for i in df.index}

    for idx, row in df.iterrows():
        # --- Date Validation ---
        try:
            year, month, day = int(row['Year']), int(row['Month']), int(row['Day'])
            pd.Timestamp(year=year, month=month, day=day)
        except ValueError:
            errors_dict[idx].append("Invalid Date (Year/Month/Day combination)")
        except Exception:
            errors_dict[idx].append("Date fields must be numeric")

        # --- Time Validation ---
        # Format HH:MM:SS or H:MM:SS (allows 1 or 2 digits for hour)
        time_val = str(row['Time']).strip()
        # regex: start, 1 or 2 digits, colon, 2 digits, colon, 2 digits, end
        if not re.match(r'^\d{1,2}:\d{2}:\d{2}$', time_val):
            errors_dict[idx].append("Time must be in HH:MM:SS or H:MM:SS format")

        # --- Direction ---
        direction = str(row['Direction']).strip().lower()
        if direction not in ['sender', 'receiver']:
            errors_dict[idx].append("Direction must be 'sender' or 'receiver'")

        # --- Financial Action ---
        action = str(row['Financial Action']).strip().lower()
        if action not in ['token_transfer', 'gas']:
            errors_dict[idx].append("Financial Action must be 'token_transfer' or 'gas'")

        # --- Asset Identifier ---
        # [REMOVED] The ALL CAPS check has been removed as per instructions.
        pass 

        # --- Amount ---
        # [UPDATED] Check for alphabets instead of generic numeric check
        amt_str = str(row['Amount'])
        
        # Check if the string contains any alphabetic character (a-z, A-Z)
        if re.search(r'[a-zA-Z]', amt_str):
            errors_dict[idx].append("Amount should never have any alphabet")
        else:
            # If no alphabets, check if it is positive (if it can be converted)
            try:
                amt = float(row['Amount'])
                if amt <= 0:
                    errors_dict[idx].append("Amount must be a positive number")
            except ValueError:
                # Value is not a number but contains no alphabets (e.g. special chars like "$"), 
                # ignoring generic "must be numeric" error as requested.
                pass

        # --- Fiat Currency ---
        fiat = row['Fiat Currency']
        if pd.notna(fiat) and str(fiat).strip():
            if str(fiat).strip().lower() not in ['usd', 'eur', 'gbp']:
                errors_dict[idx].append("Fiat Currency must be 'usd', 'eur', or 'gbp'")

        # --- Fiat Value ---
        fiat_val = row['Fiat Value (optional)']
        if pd.notna(fiat_val) and str(fiat_val).strip():
             try:
                 float(fiat_val)
             except ValueError:
                 errors_dict[idx].append("Fiat Value must be numeric")

    # 3. Consistency Checks (Group by Transaction Hash)
    if 'Transaction Hash' in df.columns:
        grouped = df.groupby('Transaction Hash')
        
        for hash_val, group in grouped:
            # Check Time Consistency
            if group['Time'].nunique() > 1:
                for idx in group.index:
                    errors_dict[idx].append(f"Time inconsistent for Hash {hash_val}")

            # Check Function Name Consistency
            if group['Function Name'].nunique() > 1:
                for idx in group.index:
                    errors_dict[idx].append(f"Function Name inconsistent for Hash {hash_val}")

            # Check Method ID Consistency 
            if group['Method ID'].nunique() > 1:
                for idx in group.index:
                    errors_dict[idx].append(f"Method ID inconsistent for Hash {hash_val}")

            # Check Transfer ID Uniqueness within Hash
            if group['Transfer ID'].duplicated().any():
                dupes = group[group.duplicated(subset=['Transfer ID'], keep=False)]
                for idx in dupes.index:
                    errors_dict[idx].append(f"Duplicate Transfer ID for Hash {hash_val}")

    # 4. Compile Errors into DataFrame
    total_errors = 0
    for idx, errors in errors_dict.items():
        if errors:
            annotated_df.at[idx, 'Validation Errors'] = "; ".join(errors)
            total_errors += len(errors)
        else:
            annotated_df.at[idx, 'Validation Errors'] = "OK"

    return annotated_df, total_errors

# --- Streamlit UI ---

st.title("📂 TRES Import File Validator")
st.markdown("""
This app validates your CSV file against the TRES Import Template rules.
**Instructions:**
1. Upload your filled `Import Template` CSV file.
2. The app will check for formatting errors.
3. If errors are found, you can download the file with a new **'Validation Errors'** column.
""")

uploaded_file = st.file_uploader("Upload CSV File", type=["csv"])

if uploaded_file is not None:
    try:
        # Load Data
        df = pd.read_csv(uploaded_file)
        
        # Strip whitespace from column names to be safe
        df.columns = df.columns.str.strip()
        
        st.write("### File Preview")
        st.dataframe(df.head())

        if st.button("Validate File"):
            with st.spinner("Validating..."):
                validated_df, error_count = validate_csv(df)

                if validated_df is not None:
                    if error_count == 0:
                        st.success("✅ The file is validated and has no errors. It is ready to upload.")
                    else:
                        st.error(f"❌ Found {error_count} errors in the file.")
                        
                        # Filter to show only rows with errors
                        error_rows = validated_df[validated_df['Validation Errors'] != "OK"]
                        
                        st.write("### Error Report")
                        st.write("Below are the rows containing errors:")
                        st.dataframe(error_rows.style.applymap(lambda x: 'background-color: #ffcccc' if x != "OK" else '', subset=['Validation Errors']))
                        
                        # Download Button
                        csv = validated_df.to_csv(index=False).encode('utf-8')
                        st.download_button(
                            label="📥 Download Validated File (with Errors)",
                            data=csv,
                            file_name="validated_file_with_errors.csv",
                            mime="text/csv",
                        )
                        
    except Exception as e:
        st.error(f"An error occurred while processing the file: {e}")
