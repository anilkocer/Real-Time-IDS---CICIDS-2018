import csv
import time
from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict
from joblib import load
import pandas as pd
from sklearn.preprocessing import LabelEncoder

# Özellik isimlerini yükleme
features_list = [
    'Dst Port', 'Protocol', 'Flow Duration', 'Tot Fwd Pkts',
    'Tot Bwd Pkts', 'TotLen Fwd Pkts', 'TotLen Bwd Pkts', 'Fwd Pkt Len Max', 
    'Fwd Pkt Len Min', 'Fwd Pkt Len Mean', 'Fwd Pkt Len Std', 'Bwd Pkt Len Max', 
    'Bwd Pkt Len Min', 'Bwd Pkt Len Mean', 'Bwd Pkt Len Std', 'Flow Byts/s', 
    'Flow Pkts/s', 'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags', 
    'Fwd Header Len', 'Bwd Header Len', 'Fwd Pkts/s', 'Bwd Pkts/s', 'Pkt Len Min', 
    'Pkt Len Max', 'Pkt Len Mean', 'Pkt Len Std', 'Pkt Len Var', 'FIN Flag Cnt', 
    'SYN Flag Cnt', 'RST Flag Cnt', 'PSH Flag Cnt', 'ACK Flag Cnt', 'URG Flag Cnt', 
    'CWE Flag Count', 'ECE Flag Cnt', 'Down/Up Ratio', 'Pkt Size Avg', 'Fwd Seg Size Avg', 
    'Bwd Seg Size Avg', 'Fwd Byts/b Avg', 'Fwd Pkts/b Avg', 'Fwd Blk Rate Avg', 
    'Bwd Byts/b Avg', 'Bwd Pkts/b Avg', 'Bwd Blk Rate Avg', 'Subflow Fwd Pkts', 
    'Subflow Fwd Byts', 'Subflow Bwd Pkts', 'Subflow Bwd Byts', 'Init Fwd Win Byts', 
    'Init Bwd Win Byts', 'Fwd Act Data Pkts', 'Fwd Seg Size Min'
]

# Bayrak karakterleri ile bayrak sayacı isimlerini eşleştiren sözlük
flags_dict = {
    'F': 'fin_flag_cnt',
    'S': 'syn_flag_cnt',
    'R': 'rst_flag_cnt',
    'P': 'psh_flag_cnt',
    'A': 'ack_flag_cnt',
    'U': 'urg_flag_cnt',
    'E': 'ece_flag_cnt',
    'C': 'cwe_flag_cnt',
    'N': '',  # Bu bayrak için bir sayac olmayacak
}

# Her akışın verilerini saklamak için bir veri yapısı
flows = defaultdict(lambda: {
    "start_time": None,
    "end_time": None,
    "tot_fwd_pkts": 0,
    "tot_bwd_pkts": 0,
    "totlen_fwd_pkts": 0,
    "totlen_bwd_pkts": 0,
    "fin_flag_cnt": 0,
    "syn_flag_cnt": 0,
    "rst_flag_cnt": 0,
    "psh_flag_cnt": 0,
    "ack_flag_cnt": 0,
    "urg_flag_cnt": 0,
    "cwe_flag_cnt": 0,
    "ece_flag_cnt": 0,
    "pkt_len_min": float('inf'),  # Başlangıçta sonsuz kabul edilir
    "pkt_len_max": 0,  # Başlangıçta sıfır kabul edilir
    "fwd_pkt_len_list": [],  # İleri paket uzunlukları
    "bwd_pkt_len_list": []   # Geri paket uzunlukları
})

# input.csv dosyası başlıkları
input_csv_headers = features_list

# input.csv dosyasını açıp başlıkları yazma
csv_filename = 'input.csv'
csv_file = open(csv_filename, mode='w', newline='')
writer = csv.DictWriter(csv_file, fieldnames=input_csv_headers)
writer.writeheader()

# output.csv dosyası başlıkları
output_csv_headers = features_list + ['Prediction', 'Benign Probability', 'Attack Probability']

# output.csv dosyasını açma
output_csv_filename = 'output.csv'
output_csv_file = open(output_csv_filename, mode='w', newline='')
output_writer = csv.DictWriter(output_csv_file, fieldnames=output_csv_headers)
output_writer.writeheader()

# Modelin yüklenmesi
model_filename = 'C:\\Users\\anilk\\OneDrive\\Masaüstü\\deneme\\gradient_boosting_model1.pkl'  # Model dosya adı ve yolunu buraya girin
clf = load(model_filename)

# Scaler'ı yükleme
scaler_filename = 'C:\\Users\\anilk\\OneDrive\\Masaüstü\\deneme\\scaler1.pkl'  # Scaler dosya adı ve yolunu buraya girin
scaler = load(scaler_filename)

# LabelEncoder'ı yükleme
label_encoder_filename = 'C:\\Users\\anilk\\OneDrive\\Masaüstü\\deneme\\label_encoder1.pkl'  # LabelEncoder dosya adı ve yolunu buraya girin
le = load(label_encoder_filename)

# Paket işleme fonksiyonu
def process_packet(packet):
    global writer, output_writer, clf, scaler, le  # writer, output_writer, clf, scaler ve le değişkenlerini global olarak işaret ediyoruz
    
    if IP in packet:
        ip_layer = packet[IP]
        
        if TCP in packet:
            tcp_layer = packet[TCP]
            protocol = 'TCP'
            pkt_len = len(packet)
            
            # TCP bayraklarını sayma
            flags = tcp_layer.flags
            
        elif UDP in packet:
            udp_layer = packet[UDP]
            protocol = 'UDP'
            pkt_len = len(packet)
            
        elif ICMP in packet:
            icmp_layer = packet[ICMP]
            protocol = 'ICMP'
            pkt_len = len(packet)
            
        else:
            return
        
        flow_key = (ip_layer.src, ip_layer.dst, ip_layer.proto)
        
        if flows[flow_key]["start_time"] is None:
            flows[flow_key]["start_time"] = time.time()
        
        flows[flow_key]["end_time"] = time.time()
        
        if protocol == 'TCP':
            flows[flow_key]["tot_fwd_pkts"] += 1
            flows[flow_key]["totlen_fwd_pkts"] += pkt_len
            flows[flow_key]["fwd_pkt_len_list"].append(pkt_len)
            
            # TCP bayraklarını sayma
            for flag_char, count_key in flags_dict.items():
                if flag_char in flags:
                    flows[flow_key][count_key] += 1
        
        elif protocol == 'UDP':
            flows[flow_key]["tot_bwd_pkts"] += 1
            flows[flow_key]["totlen_bwd_pkts"] += pkt_len
            flows[flow_key]["bwd_pkt_len_list"].append(pkt_len)
        
        elif protocol == 'ICMP':
            flows[flow_key]["tot_fwd_pkts"] += 1
            flows[flow_key]["totlen_fwd_pkts"] += pkt_len
            flows[flow_key]["fwd_pkt_len_list"].append(pkt_len)
        
        # Paket uzunluğunu kontrol etme
        if pkt_len < flows[flow_key]["pkt_len_min"]:
            flows[flow_key]["pkt_len_min"] = pkt_len
        
        if pkt_len > flows[flow_key]["pkt_len_max"]:
            flows[flow_key]["pkt_len_max"] = pkt_len
        
        # Özellikleri hesaplama
        flow_duration = flows[flow_key]["end_time"] - flows[flow_key]["start_time"]
        flow_byts_s = flows[flow_key]["totlen_fwd_pkts"] / flow_duration if flow_duration > 0 else 0
        flow_pkts_s = flows[flow_key]["tot_fwd_pkts"] / flow_duration if flow_duration > 0 else 0
        pkt_len_mean = sum(flows[flow_key]["fwd_pkt_len_list"] + flows[flow_key]["bwd_pkt_len_list"]) / (len(flows[flow_key]["fwd_pkt_len_list"]) + len(flows[flow_key]["bwd_pkt_len_list"]))
        pkt_len_std = (sum([(x - pkt_len_mean) ** 2 for x in flows[flow_key]["fwd_pkt_len_list"] + flows[flow_key]["bwd_pkt_len_list"]]) / (len(flows[flow_key]["fwd_pkt_len_list"]) + len(flows[flow_key]["bwd_pkt_len_list"]))) ** 0.5
        pkt_len_var = pkt_len_std ** 2
        
        # Özelliklerin yazılması
        feature = {
            'Dst Port': tcp_layer.dport if protocol == 'TCP' else udp_layer.dport if protocol == 'UDP' else 0,
            'Protocol': 6 if protocol == 'TCP' else 17 if protocol == 'UDP' else 1 if protocol == 'ICMP' else 0,
            'Flow Duration': flow_duration,
            'Tot Fwd Pkts': flows[flow_key]["tot_fwd_pkts"],
            'Tot Bwd Pkts': flows[flow_key]["tot_bwd_pkts"],
            'TotLen Fwd Pkts': flows[flow_key]["totlen_fwd_pkts"],
            'TotLen Bwd Pkts': flows[flow_key]["totlen_bwd_pkts"],
            'Fwd Pkt Len Max': max(flows[flow_key]["fwd_pkt_len_list"]) if flows[flow_key]["fwd_pkt_len_list"] else 0,
            'Fwd Pkt Len Min': min(flows[flow_key]["fwd_pkt_len_list"]) if flows[flow_key]["fwd_pkt_len_list"] else 0,
            'Fwd Pkt Len Mean': sum(flows[flow_key]["fwd_pkt_len_list"]) / len(flows[flow_key]["fwd_pkt_len_list"]) if flows[flow_key]["fwd_pkt_len_list"] else 0,
            'Fwd Pkt Len Std': (sum([(x - (sum(flows[flow_key]["fwd_pkt_len_list"]) / len(flows[flow_key]["fwd_pkt_len_list"]))) ** 2 for x in flows[flow_key]["fwd_pkt_len_list"]]) / len(flows[flow_key]["fwd_pkt_len_list"])) ** 0.5 if len(flows[flow_key]["fwd_pkt_len_list"]) > 1 else 0,
            'Bwd Pkt Len Max': max(flows[flow_key]["bwd_pkt_len_list"]) if flows[flow_key]["bwd_pkt_len_list"] else 0,
            'Bwd Pkt Len Min': min(flows[flow_key]["bwd_pkt_len_list"]) if flows[flow_key]["bwd_pkt_len_list"] else 0,
            'Bwd Pkt Len Mean': sum(flows[flow_key]["bwd_pkt_len_list"]) / len(flows[flow_key]["bwd_pkt_len_list"]) if flows[flow_key]["bwd_pkt_len_list"] else 0,
            'Bwd Pkt Len Std': (sum([(x - (sum(flows[flow_key]["bwd_pkt_len_list"]) / len(flows[flow_key]["bwd_pkt_len_list"]))) ** 2 for x in flows[flow_key]["bwd_pkt_len_list"]]) / len(flows[flow_key]["bwd_pkt_len_list"])) ** 0.5 if len(flows[flow_key]["bwd_pkt_len_list"]) > 1 else 0,
            'Flow Byts/s': flow_byts_s,
            'Flow Pkts/s': flow_pkts_s,
            'Fwd PSH Flags': flows[flow_key]["psh_flag_cnt"],
            'Bwd PSH Flags': flows[flow_key]["psh_flag_cnt"],
            'Fwd URG Flags': flows[flow_key]["urg_flag_cnt"],
            'Bwd URG Flags': flows[flow_key]["urg_flag_cnt"],
            'Fwd Header Len': 0,  # Bu özelliği hesaplarken ağ paketlerini analiz etmeniz gerekebilir
            'Bwd Header Len': 0,  # Bu özelliği hesaplarken ağ paketlerini analiz etmeniz gerekebilir
            'Fwd Pkts/s': flows[flow_key]["tot_fwd_pkts"] / flow_duration if flow_duration > 0 else 0,
            'Bwd Pkts/s': flows[flow_key]["tot_bwd_pkts"] / flow_duration if flow_duration > 0 else 0,
            'Pkt Len Min': flows[flow_key]["pkt_len_min"],
            'Pkt Len Max': flows[flow_key]["pkt_len_max"],
            'Pkt Len Mean': pkt_len_mean,
            'Pkt Len Std': pkt_len_std,
            'Pkt Len Var': pkt_len_var,
            'FIN Flag Cnt': flows[flow_key]["fin_flag_cnt"],
            'SYN Flag Cnt': flows[flow_key]["syn_flag_cnt"],
            'RST Flag Cnt': flows[flow_key]["rst_flag_cnt"],
            'PSH Flag Cnt': flows[flow_key]["psh_flag_cnt"],
            'ACK Flag Cnt': flows[flow_key]["ack_flag_cnt"],
            'URG Flag Cnt': flows[flow_key]["urg_flag_cnt"],
            'CWE Flag Count': flows[flow_key]["cwe_flag_cnt"],
            'ECE Flag Cnt': flows[flow_key]["ece_flag_cnt"],
            'Down/Up Ratio': (flows[flow_key]["tot_fwd_pkts"] / flows[flow_key]["tot_bwd_pkts"]) if flows[flow_key]["tot_bwd_pkts"] > 0 else 0,
            'Pkt Size Avg': pkt_len_mean,
            'Fwd Seg Size Avg': sum(flows[flow_key]["fwd_pkt_len_list"]) / len(flows[flow_key]["fwd_pkt_len_list"]) if flows[flow_key]["fwd_pkt_len_list"] else 0,
            'Bwd Seg Size Avg': sum(flows[flow_key]["bwd_pkt_len_list"]) / len(flows[flow_key]["bwd_pkt_len_list"]) if flows[flow_key]["bwd_pkt_len_list"] else 0,
            'Fwd Byts/b Avg': flows[flow_key]["totlen_fwd_pkts"] / flows[flow_key]["tot_fwd_pkts"] if flows[flow_key]["tot_fwd_pkts"] > 0 else 0,
            'Fwd Pkts/b Avg': len(flows[flow_key]["fwd_pkt_len_list"]) / flows[flow_key]["tot_fwd_pkts"] if flows[flow_key]["tot_fwd_pkts"] > 0 else 0,
            'Fwd Blk Rate Avg': 0,  # Bu özelliği hesaplarken ağ paketlerini analiz etmeniz gerekebilir
            'Bwd Byts/b Avg': flows[flow_key]["totlen_bwd_pkts"] / flows[flow_key]["tot_bwd_pkts"] if flows[flow_key]["tot_bwd_pkts"] > 0 else 0,
            'Bwd Pkts/b Avg': len(flows[flow_key]["bwd_pkt_len_list"]) / flows[flow_key]["tot_bwd_pkts"] if flows[flow_key]["tot_bwd_pkts"] > 0 else 0,
            'Bwd Blk Rate Avg': 0,  # Bu özelliği hesaplarken ağ paketlerini analiz etmeniz gerekebilir
            'Subflow Fwd Pkts': 0,  # Bu özelliği hesaplarken ağ paketlerini analiz etmeniz gerekebilir
            'Subflow Fwd Byts': 0,  # Bu özelliği hesaplarken ağ paketlerini analiz etmeniz gerekebilir
            'Subflow Bwd Pkts': 0,  # Bu özelliği hesaplarken ağ paketlerini analiz etmeniz gerekebilir
            'Subflow Bwd Byts': 0,  # Bu özelliği hesaplarken ağ paketlerini analiz etmeniz gerekebilir
            'Init Fwd Win Byts': 0,  # Bu özelliği hesaplarken ağ paketlerini analiz etmeniz gerekebilir
            'Init Bwd Win Byts': 0,  # Bu özelliği hesaplarken ağ paketlerini analiz etmeniz gerekebilir
            'Fwd Act Data Pkts': 0,  # Bu özelliği hesaplarken ağ paketlerini analiz etmeniz gerekebilir
            'Fwd Seg Size Min': min(flows[flow_key]["fwd_pkt_len_list"]) if flows[flow_key]["fwd_pkt_len_list"] else 0,
        }
        
        # CSV'ye yazma
        writer.writerow(feature)
        
        # Öznitelikleri normalize etme ve modelle tahmin yapma
        feature_df = pd.DataFrame([feature])
        feature_df_scaled = scaler.transform(feature_df)
        prediction = clf.predict(feature_df_scaled)
        prediction_proba = clf.predict_proba(feature_df_scaled)
        
        # Sonuçları yazdırma
        print(f"Tahmin edilen sınıf: {le.inverse_transform([prediction])[0]}")
        print(f"Benign Olasılığı: {prediction_proba[0][0] * 100:.2f}%")
        print(f"Attack Olasılığı: {prediction_proba[0][1] * 100:.2f}%")
        
        # Çıktıları CSV'ye yazma
        output_feature = feature.copy()
        output_feature.update({
            'Prediction': prediction[0],
            'Benign Probability': prediction_proba[0][0],
            'Attack Probability': prediction_proba[0][1],
        })
        output_writer.writerow(output_feature)

# Ağ trafiğini dinleme
sniff(prn=process_packet)

