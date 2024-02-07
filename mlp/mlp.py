import torch
import torch.nn as nn
import torch.optim as optim
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

dataset = pd.read_csv('dataset.csv')

features = dataset.iloc[:, :-1].values
labels = dataset.iloc[:, -1].values

scaler = StandardScaler()
features = scaler.fit_transform(features)

labels = (labels / 5).astype(int)

X_train, X_test, y_train, y_test = train_test_split(features, labels, test_size=0.33, random_state=42)

X_train = torch.Tensor(X_train)
y_train = torch.LongTensor(y_train)
X_test = torch.Tensor(X_test)
y_test = torch.LongTensor(y_test)

class MLP(nn.Module):
    def __init__(self, input_size, hidden_size, num_classes):
        super(MLP, self).__init__()
        self.fc1 = nn.Linear(input_size, hidden_size)
        self.relu = nn.ReLU()
        self.fc2 = nn.Linear(hidden_size, num_classes)

    def forward(self, x):
        out = self.fc1(x)
        out = self.relu(out)
        out = self.fc2(out)
        return out

input_size = 6
hidden_size = 6
num_classes = 21

model = MLP(input_size, hidden_size, num_classes)

criterion = nn.CrossEntropyLoss()
optimizer = optim.Adam(model.parameters(), lr=0.1)

num_epochs = 1000

# Training
for epoch in range(num_epochs):

    # Forward pass
    outputs = model(X_train)
    loss = criterion(outputs, y_train)

    # Backward and optimize
    optimizer.zero_grad()
    loss.backward()
    optimizer.step()

    # Training accuracy
    _, predicted_train = torch.max(outputs.data, 1)
    correct_train = (predicted_train == y_train).sum().item()
    accuracy_train = correct_train / y_train.size(0)
    print(f"Epoch [{epoch + 1}/{num_epochs}], Loss: {loss.item():.4f}, Training Accuracy: {accuracy_train * 100:.2f}%")

# Testing
with torch.no_grad():

    outputs = model(X_test)
    _, predicted = torch.max(outputs.data, 1)

    # Calculate accuracy
    accuracy = (predicted == y_test).sum().item() / y_test.size(0)
    print(f"Accuracy on test set: {accuracy*100:.2f}%")
