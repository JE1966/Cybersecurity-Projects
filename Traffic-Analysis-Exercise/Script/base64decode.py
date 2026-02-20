import base64

prefix = "ping|STRRAT|1BE8292C|DESKTOP-SKBR25F|ccollier|Microsoft Windows 11 Pro|64-bit|Windows Defender|" # Each line starts with the same prefix

seen_encoded = set() # Store each distinct encoded string to avoid processing them repeatedly

with open("flagged_TCP_traffic", "r", encoding="utf-8") as readfile,  open("decoded_traffic", "w", encoding="utf-8") as writefile:
	
	writefile.write("|Encoded|Decoded|\n|---|---|\n") #Table header in markdown

	for line in readfile:
		line = line.strip()

		if line.startswith(prefix):
			rest = line[len(prefix):]
			encoded = rest.split("|", 1)[0] # Extract the substring immediately after the prefix up to the next pipe
 
			if encoded in seen_encoded: # Skip if we've already seen this encoded substring
				continue 
			seen_encoded.add(encoded)
			
			try:
				decoded = base64.b64decode(encoded).decode("utf-8")
				writefile.write(f"|{encoded}|{decoded}|\n")
			except Exception: # Skip strings that are not base64 encoded if encountered
				writefile.write(f"|{encoded}|<not valid base64>|\n")
