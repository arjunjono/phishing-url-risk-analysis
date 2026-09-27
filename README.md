# phishing-url-risk-analysis
EDA on 11,430 real URLs testing whether simple red flags can predict phishing without ML.

Looking at 11,430 real URLs (half phishing, half legit) to see if you
can actually predict whether a url is phishing just from simple stuff
in the url itself, no clicking the link or scanning the page.

data:
Got this from a phishing detection research dataset by Hannousse &
Yahiouche (2021), public on Mendeley Data:
https://data.mendeley.com/datasets/c2gw7fy2j4/3

Full dataset has 89 columns, I only kept 13 of them since those
were the ones I could actually explain. Stuff like url length, if the
hostname is a raw ip address, if there's an @ symbol, if it uses a
link shortener, if the domain ending is one phishers use a lot, and
the status column which just tells you if it's actually phishing or
legit.

questions I had:
1: what % of the data is phishing vs legit
2: are phishing urls longer than legit ones on average
3: which red flags show up more in phishing urls
4: if you count up the red flags into a risk score, does it actually work

what I found:
phishing urls average 74.9 characters, legit ones average 47.4
most common single red flag was a misleading https in the url text,
66.7% of phishing urls had it
the risk score actually works. urls with 0 flags were phishing 23.6%
of the time, urls with 3+ flags were phishing 89.2% of the time

this is just eda + a risk score I built by hand, not machine learning.
i picked the rule myself by looking at the data, nothing here trained
itself.

running it:
pip install -r requirements.txt
python phishing_etl.py

needs phishing_urls.csv in the same folder. running it regenerates
findings_summary.txt, urls_with_risk_scores.csv, and the 4 png charts.
running it regenerates findings_summary.txt, urls_with_risk_scores.csv, and the 4 png charts.
