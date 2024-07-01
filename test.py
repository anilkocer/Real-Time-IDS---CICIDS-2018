from joblib import load
import pandas as pd

# Modeli yükleme
model_filename = 'C:\\Users\\anilk\\OneDrive\\Masaüstü\\RealTimeIds\\gradient_boosting_model.pkl'
clf = load(model_filename)

# CSV dosyasını okuma
input_csv_filename = 'input.csv'
data = pd.read_csv(input_csv_filename)

# Girdi verilerini X olarak tanımlama
X = data.drop(['Timestamp'], axis=1)  # Model eğitirken kullanılan sütunlara dikkat edin

# Model ile sınıflandırma yapma
y_pred = clf.predict(X)

# Sınıflandırma sonuçlarını yeni bir sütun olarak ekleyebilir veya yeni bir DataFrame'e yazabilirsiniz
data['Prediction'] = y_pred

# Sınıflandırma sonuçlarını yeni bir CSV dosyasına yazma
output_csv_filename = 'output.csv'
data.to_csv(output_csv_filename, index=False)

label_counts = data['Prediction'].value_counts()
print(label_counts)

