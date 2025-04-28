import pandas as pd

# 加载第一个训练数据集文件
df1 = pd.read_csv("DDoS_data_0.csv")
print("First training dataset:")
print(df1.head())

# 加载第二个训练数据集文件
df2 = pd.read_csv("DDoS_data_1.csv")
print("\nSecond training dataset:")
print(df2.head())

