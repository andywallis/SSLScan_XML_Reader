# Output in Typst format
python3 script.py -f sslscan_output.xml -o typst > findings.typ

# Filter to only high/critical severity in Typst format
python3 script.py -f sslscan_output.xml -o typst --min-severity high
