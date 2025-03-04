# network-monitoring
Network monitoring dashboard built with Python. This project is a real-time network traffic analysis tool built with Python, Scapy, and Streamlit. It captures and visualizes network packets, providing insights into protocol distribution, traffic trends, and top source IPs. The dashboard updates dynamically, displaying recent packets and key network metrics. 
## Installation and Usage
**Make sure you have python and pip installed.**
1. Clone or download the repo
```
git clone git@github.com:rhenzala/network-monitoring.git
```
2. Active virtual environment
```
python3 -m venv .venv
source .venv/bin/activate
```
3. Install dependencies
```
pip install -r requirements.txt
```
4. Run the program
```
sudo streamlit run app.py
```
if `streamlit` is installed in virtual environment, run the following and copy the output:
```
which streamlit
```
then:
```
sudo <path to streamlit> run app.py
```
## Attribution
This project is a reimplementation of the code from a<a href="https://www.freecodecamp.org/news/build-a-real-time-network-traffic-dashboard-with-python-and-streamlit/">freeCodeCamp article</a>, that does not use Classes. 

