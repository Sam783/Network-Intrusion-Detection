import streamlit as st
import numpy as np
import pandas as pd
import pickle
from sklearn.preprocessing import StandardScaler
from PIL import Image
normal = Image.open("Images/normal.png")
attack = Image.open("Images/attack.png")

model = pickle.load(open('model.pkl', 'rb'))
scale = pickle.load(open('scaler.pkl', 'rb'))


attack_mapping = {'OTH': 0, 'REJ': 1, 'RSTO': 2, 'RSTOS0': 3, 'RSTR': 4, 'S0': 5, 'S1': 6, 'S2': 7, 'S3': 8, 'SF': 9, 'SH': 10}
service_mapping = {'IRC': 0, 'X11': 1, 'Z39_50': 2, 'auth': 3, 'bgp': 4, 'courier': 5, 'csnet_ns': 6,
 'ctf': 7, 'daytime': 8, 'discard': 9, 'domain': 10, 'domain_u': 11, 'echo': 12, 
'eco_i': 13, 'ecr_i': 14, 'efs': 15, 'exec': 16, 'finger': 17, 'ftp': 18, 'ftp_data': 19,
 'gopher': 20, 'hostnames': 21, 'http': 22, 'http_443': 23, 'imap4': 24, 'iso_tsap': 25,
 'klogin': 26, 'kshell': 27, 'ldap': 28, 'link': 29, 'login': 30, 'mtp': 31, 'name': 32, 
'netbios_dgm': 33, 'netbios_ns': 34, 'netbios_ssn': 35, 'netstat': 36, 'nnsp': 37, 'nntp': 38, 
'ntp_u': 39, 'other': 40, 'pm_dump': 41, 'pop_2': 42, 'pop_3': 43, 'printer': 44, 'private': 45, 
'remote_job': 46, 'rje': 47, 'shell': 48, 'smtp': 49, 'sql_net': 50, 'ssh': 51, 'sunrpc': 52, 
'supdup': 53, 'systat': 54, 'telnet': 55, 'tftp_u': 56, 'tim_i': 57, 'time': 58, 'urp_i': 59, 
'uucp': 60, 'uucp_path': 61, 'vmnet': 62, 'whois': 63
}
protocol_mapping = {'icmp': 0, 'tcp': 1, 'udp': 2}


st.title("Network Intrusion Detection")
protocol_type = st.text_input("Type of Protocol:")
service = st.text_input("Type of Service:")
flag = st.text_input("Type of flag:")
src_bytes = st.text_input("value of src_bytes:")
dst_bytes = st.text_input("value of dst_bytes:")
count = st.text_input("count:")
same_srv_rate = st.text_input("same_srv_rate:")
diff_srv_rate = st.text_input("diff_srv_rate:")
dst_host_srv_count = st.text_input("dst_host_srv_count:")
dst_host_same_srv_rate = st.text_input("dst_host_same_srv_rate:")

if st.button('Predict'):
    data = {
        'protocol_type': [protocol_mapping.get(protocol_type, protocol_type)],
        'service': [service_mapping.get(service, service)],
        'flag': [attack_mapping.get(flag, flag)],
        'src_bytes': [float(src_bytes)],
        'dst_bytes': [float(dst_bytes)],
        'count': [float(count)],
        'same_srv_rate': [float(same_srv_rate)],
        'diff_srv_rate': [float(diff_srv_rate)],
        'dst_host_srv_count': [float(dst_host_srv_count)],
        'dst_host_same_srv_rate': [float(dst_host_same_srv_rate)],
    }

    df = pd.DataFrame(data)
    st.dataframe(df)
    print(df)
    X_scaled = scale.transform(df)
    print(X_scaled)
    result = model.predict(X_scaled)
    print(result)
    if result == 1:
        st.image(normal, width=600)
        st.header("Normal Class")
    else:
        st.image(attack, width=600)
        st.header("Attack Class")
