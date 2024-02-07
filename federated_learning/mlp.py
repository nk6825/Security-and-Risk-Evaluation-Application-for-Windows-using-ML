import torch
import torch.nn as nn
import torch.optim as optim
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

dataset1 = pd.read_csv('dataset1.csv')
dataset2 = pd.read_csv('dataset2.csv')
dataset3 = pd.read_csv('dataset3.csv')
dataset4 = pd.read_csv('dataset4.csv')

input_size = 6
hidden_size = 60
num_classes = 21

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

def preprocess(dataset):
    features = dataset.iloc[:, :-1].values
    labels = dataset.iloc[:, -1].values

    scaler = StandardScaler()
    features = scaler.fit_transform(features)

    labels = (labels / 5).astype(int)

    return list(train_test_split(features, labels, test_size=0.33, random_state=42))

def train(dataset, model, n):

    X_train = torch.Tensor(dataset[0])
    X_test = torch.Tensor(dataset[1])
    y_train = torch.LongTensor(dataset[2])
    y_test = torch.LongTensor(dataset[3])

    criterion = nn.CrossEntropyLoss()
    optimizer = optim.Adam(model.parameters(), lr=0.1)

    num_epochs = 30

    print("\nModel ", n, "\n")
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

    return model


def aggregate_models(models):
    # Create a new model for aggregation
    aggregated_model = MLP(input_size, hidden_size, num_classes)

    # Iterate through the layers of the models
    for aggregated_param, model_params in zip(aggregated_model.parameters(), zip(*[model.parameters() for model in models])):
        # Average the weights of each layer
        aggregated_param.data.copy_(torch.mean(torch.stack(model_params), dim=0))

    return aggregated_model

def main():
    model = MLP(input_size, hidden_size, num_classes)
    d1 = preprocess(dataset1)
    d2 = preprocess(dataset2)
    d3 = preprocess(dataset3)
    d4 = preprocess(dataset4)
    for i in range(10):
        print("\nRound ", i + 1)
        model1 = train(d1, model, 1)
        model2 = train(d2, model, 2)
        model3 = train(d3, model, 3)
        model4 = train(d4, model, 4)
        model = aggregate_models([model1, model2, model3, model4])

if __name__ == '__main__':
    main()
