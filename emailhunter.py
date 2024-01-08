import re
import requests

# Define the domain you want to check
target_domain = "something"

# Function to check if an email address is publicly available on the internet
def check_email_presence(email):
    # Construct the URL to check
    url = f"https://www.google.com/search?q={email}"
    
    # Send a request to Google search
    response = requests.get(url)
    
    # Check if the email address is present in the search results
    if email in response.text:
        return f"Email address {email} is publicly available."
    else:
        return f"Email address {email} is not publicly available."

# Function to generate a list of email addresses from the given domain
def generate_email_list(domain):
    return [f"user{i}@{domain}" for i in range(1, 6)]  # Adjust the range as needed

# Generate a list of email addresses from the target domain
email_addresses = generate_email_list(target_domain)

# Loop through the list of email addresses and check their presence
for email in email_addresses:
    result = check_email_presence(email)
    print(result)
