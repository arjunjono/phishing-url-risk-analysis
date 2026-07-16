# Phishing URL ETL Project
# Dataset: 11,430 real URLs (5715 phishing, 5715 legit) from a phishing
# detection research paper (Hannousse & Yahiouche 2021). csv needs to
# be in the same folder as this file: phishing_urls.csv

# columns I'm using:
# length_url - how many characters the url has
# ip - is the hostname just a raw ip address (like http://192.168.1.1/)
# nb_at - number of @ symbols in the url
# https_token - if "https" shows up somewhere weird in the url text
# prefix_suffix - hyphen used to fake a brand name, like paypal-secure.com
# shortening_service - used a link shortener like bit.ly
# suspicious_tld - domain ending that phishers use a lot

# questions I wanted to answer:
# 1. how much of the data is actually phishing vs legit
# 2. are phishing urls longer on average
# 3. which red flags show up more in phishing urls
# 4. if i add up the red flags into a "risk score" does it actually work

import pandas as pd
import matplotlib.pyplot as plt

# EXTRACT 
# just reading the csv into a dataframe
urls_df = pd.read_csv("phishing_urls.csv")

print(urls_df.head())
print(urls_df.columns)
print(f"Total URLs loaded: {len(urls_df)}\n")


# TRANSFORM

# split into two dataframes based on the status column
phishing_df = urls_df[urls_df["status"] == "phishing"]
legit_df = urls_df[urls_df["status"] == "legitimate"]

num_phishing = len(phishing_df)
num_legit = len(legit_df)
percent_phishing = (num_phishing / len(urls_df)) * 100

# q2 - avg url length for each group
avg_length_phishing = phishing_df["length_url"].mean()
avg_length_legit = legit_df["length_url"].mean()

# q3 - checking how often each red flag shows up in each group
# these columns are just 0 or 1, so summing gives us the count
red_flags = ["ip", "nb_at", "https_token", "prefix_suffix", "shortening_service", "suspicious_tld"]

flag_percent_phishing = {}
flag_percent_legit = {}

for flag in red_flags:
    phishing_count = phishing_df[flag].sum()
    legit_count = legit_df[flag].sum()

    flag_percent_phishing[flag] = (phishing_count / num_phishing) * 100
    flag_percent_legit[flag] = (legit_count / num_legit) * 100

# find the flag with the highest percentage for phishing urls
# (just doing this manually instead of using a built in function)
top_flag = ""
top_flag_percent = 0
for flag in flag_percent_phishing:
    percent = flag_percent_phishing[flag]
    if percent > top_flag_percent:
        top_flag_percent = percent
        top_flag = flag

# q4 - risk score. for every url count how many of the 6 flags are on (0-6)
risk_scores = []

for i in range(len(urls_df)):
    row = urls_df.iloc[i]
    score = 0

    # just checking each flag one at a time, no need for a loop here
    if row["ip"] == 1:
        score = score + 1
    if row["nb_at"] > 0:
        score = score + 1
    if row["https_token"] == 1:
        score = score + 1
    if row["prefix_suffix"] == 1:
        score = score + 1
    if row["shortening_service"] == 1:
        score = score + 1
    if row["suspicious_tld"] == 1:
        score = score + 1

    risk_scores.append(score)

urls_df["risk_score"] = risk_scores

# turning the score into categories, kind of like the grade cutoffs
# activity we did with if/elif/else
risk_categories = []
for score in risk_scores:
    if score >= 3:
        risk_categories.append("High Risk")
    elif score >= 1:
        risk_categories.append("Medium Risk")
    else:
        risk_categories.append("Low Risk")

urls_df["risk_category"] = risk_categories

# now check if the score actually means anything - for each category,
# what % of urls in it were actually phishing
category_list = ["Low Risk", "Medium Risk", "High Risk"]
category_phishing_rate = {}

for category in category_list:
    category_df = urls_df[urls_df["risk_category"] == category]
    category_phishing_df = category_df[category_df["status"] == "phishing"]

    if len(category_df) > 0:
        rate = (len(category_phishing_df) / len(category_df)) * 100
    else:
        rate = 0
    category_phishing_rate[category] = rate


# LOAD 

# building the summary text as one string, adding to it as we go
summary = "PHISHING URL DATA ETL FINDINGS\n"
summary += "=" * 45 + "\n"
summary += f"Total URLs analyzed: {len(urls_df)}\n"
summary += f"Phishing URLs: {num_phishing} ({percent_phishing:.1f}%)\n"
summary += f"Legitimate URLs: {num_legit} ({100 - percent_phishing:.1f}%)\n\n"
summary += "Average URL length:\n"
summary += f"  Phishing URLs:   {avg_length_phishing:.1f} characters\n"
summary += f"  Legitimate URLs: {avg_length_legit:.1f} characters\n\n"
summary += "Red flag frequency (percent of URLs with each flag present):\n"
for flag in red_flags:
    p_percent = flag_percent_phishing[flag]
    l_percent = flag_percent_legit[flag]
    summary += f"  {flag}: {p_percent:.1f}% of phishing URLs vs {l_percent:.1f}% of legitimate URLs\n"
summary += f"\nMost common red flag in phishing URLs: '{top_flag}' "
summary += f"({top_flag_percent:.1f}% of phishing URLs have it)\n"
summary += "\nRisk score check - percent of each category that was ACTUALLY phishing:\n"
for category in category_list:
    rate = category_phishing_rate[category]
    summary += f"  {category}: {rate:.1f}% were phishing\n"
with open("findings_summary.txt", "w", encoding="utf-8") as file:
    file.write(summary)
print(summary)
print("Saved findings_summary.txt")

# saving the dataframe with the new risk score columns too
urls_df.to_csv("urls_with_risk_scores.csv", index=False)
print("Saved urls_with_risk_scores.csv")


# CHARTS 

# chart 1 - how many phishing vs legit urls are in the dataset
plt.figure(figsize=(6, 4))
plt.bar(["Legitimate", "Phishing"], [num_legit, num_phishing])
plt.title("Dataset Balance: Phishing vs Legitimate URLs")
plt.ylabel("Number of URLs")
plt.savefig("phishing_vs_legit_count.png")
plt.close()

# chart 2 - red flag % for phishing urls only
phishing_values = []
for flag in red_flags:
    phishing_values.append(flag_percent_phishing[flag])

plt.figure(figsize=(8, 5))
plt.bar(red_flags, phishing_values)
plt.title("Red Flag Frequency in PHISHING URLs")
plt.ylabel("Percent of URLs with Flag Present")
plt.xticks(rotation=30)
plt.savefig("red_flags_phishing.png")
plt.close()

# chart 3 - same thing but for legit urls, so we can compare the two charts
legit_values = []
for flag in red_flags:
    legit_values.append(flag_percent_legit[flag])

plt.figure(figsize=(8, 5))
plt.bar(red_flags, legit_values)
plt.title("Red Flag Frequency in LEGITIMATE URLs")
plt.ylabel("Percent of URLs with Flag Present")
plt.xticks(rotation=30)
plt.savefig("red_flags_legit.png")
plt.close()

# chart 4 - does the risk score actually work? higher risk = more phishing?
accuracy_values = []
for category in category_list:
    accuracy_values.append(category_phishing_rate[category])

plt.figure(figsize=(6, 4))
plt.bar(category_list, accuracy_values)
plt.title("Risk Score Accuracy: % Actually Phishing per Category")
plt.ylabel("Percent Phishing")
plt.savefig("risk_score_accuracy.png")
plt.close()

print("Saved phishing_vs_legit_count.png, red_flags_phishing.png, red_flags_legit.png, and risk_score_accuracy.png")
