import csv
import time
from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict
from joblib import load
import pandas as pd
from sklearn.preprocessing import LabelEncoder
import threading
import tkinter as tk
from tkinter import Scrollbar, ttk

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
protocol_names = {
    6: "TCP",
    17: "UDP",
    1: "ICMP"
}

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
    "start_time": time.time(),
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
        
        writer.writerow(feature)
        
        # Model tahmini ve sonuçların yazılması
        feature_df = pd.DataFrame([feature])
        feature_df_scaled = scaler.transform(feature_df)
        prediction = clf.predict(feature_df_scaled)
        prediction_prob = clf.predict_proba(feature_df_scaled)
        
        prediction_label = le.inverse_transform(prediction)
        benign_prob = prediction_prob[0][0] * 100
        attack_prob = prediction_prob[0][1] * 100
        
        feature['Prediction'] = prediction_label[0]
        feature['Benign Probability'] = benign_prob
        feature['Attack Probability'] = attack_prob
        
        output_writer.writerow(feature)
        output_csv_file.flush()  # Verilerin hemen yazılması için dosyayı temizle

# Paket koklama fonksiyonu
def sniff_packets():
    sniff(prn=process_packet, store=0)

# Tkinter GUI oluşturma
class NetworkTrafficApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Traffic Analysis")
        
        self.start_button = tk.Button(self.root, text="Start", command=self.start_sniffing)
        self.start_button.pack()
        
        self.tree = ttk.Treeview(self.root, columns=("Dst Port", "Protocol", "Flow Duration", "Tot Fwd Pkts", "Prediction", "Benign Probability"), show='headings')
        self.tree.heading("Dst Port", text="Dst Port")
        self.tree.heading("Protocol", text="Protocol")
        self.tree.heading("Flow Duration", text="Flow Duration")
        self.tree.heading("Tot Fwd Pkts", text="Tot Fwd Pkts")
        self.tree.heading("Prediction", text="Prediction")
        self.tree.heading("Benign Probability", text="Benign Probability")
        
        self.tree.pack(expand=True, fill=tk.BOTH)
        self.tree.bind("<Double-1>", self.show_packet_details)
        
        self.update_treeview()
        
    def start_sniffing(self):
        thread = threading.Thread(target=sniff_packets)
        thread.daemon = True
        thread.start()

    def update_treeview(self):
        # output.csv dosyasını oku
        try:
            data = pd.read_csv('output.csv')
            
            for i in self.tree.get_children():
                self.tree.delete(i)
                
            for index, row in data.iterrows():
                protocol = protocol_names.get(row["Protocol"], "Unknown")
                self.tree.insert("", "end", values=(row["Dst Port"], protocol, row["Flow Duration"], row["Tot Fwd Pkts"], row["Prediction"], row["Benign Probability"]))
        except Exception as e:
            print("Error:", e)
            
        self.root.after(1000, self.update_treeview)
        self.tree.yview_moveto(1)
    def show_packet_details(self, event):
        item = self.tree.selection()[0]  # Get selected item
        
        # Create a new window for details
        details_window = tk.Toplevel(self.root)
        details_window.title("Packet Details")
        
        # Fetch details from the selected item
        selected_packet_index = self.tree.index(item)
        selected_packet_details = self.fetch_packet_details(selected_packet_index)
        
        # Create a scrollable frame for details
        scroll_frame = tk.Frame(details_window)
        scroll_frame.pack(fill=tk.BOTH, expand=True)
        
        # Add a scrollbar
        scrollbar = Scrollbar(scroll_frame, orient=tk.VERTICAL)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Create a canvas to hold details
        canvas = tk.Canvas(scroll_frame, yscrollcommand=scrollbar.set)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Configure scrollbar to scroll canvas properly
        scrollbar.config(command=canvas.yview)
        
        # Create a frame inside the canvas to hold details
        detail_frame = tk.Frame(canvas)
        canvas.create_window((0, 0), window=detail_frame, anchor=tk.NW)
        
        # Display details in labels
        detail_labels = []
        for key, value in selected_packet_details.items():
            label_text = f"{key}: {value}"
            label = tk.Label(detail_frame, text=label_text, wraplength=600, justify=tk.LEFT)
            label.pack(anchor="w", padx=10, pady=5)
            detail_labels.append(label)
        
        # Bind canvas scrolling
        detail_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
    def fetch_packet_details(self, index):
        try:
            data = pd.read_csv('output.csv')
            selected_packet = data.iloc[index]
            
            # Önceki paketin zaman damgasını kontrol edin
            if hasattr(self, 'last_packet_time'):
                # Şu anki zaman damgasını alın
                current_time = time.time()
                
                # Önceki paketin zaman damgası ile şu anki zaman damgası arasındaki farkı alın
                flow_duration = current_time - self.last_packet_time
                self.last_packet_time = current_time
            else:
                # İlk paket için zaman damgasını kaydedin
                self.last_packet_time = time.time()
                flow_duration = 0.0  # Veya başka bir varsayılan değer
                
            # Diğer paket detaylarını alın
            selected_packet_details = selected_packet.to_dict()
            
            # Flow Duration değerini güncellemek için
            selected_packet_details['Flow Duration'] = flow_duration
            
            return selected_packet_details
        except Exception as e:
            print("Error fetching packet details:", e)
            return {}

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkTrafficApp(root)
    root.mainloop()