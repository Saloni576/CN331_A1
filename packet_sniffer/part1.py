import pandas as pd
import matplotlib.pyplot as plt

# Load the data
data = pd.read_csv("histogram_data.csv", header=None, names=["Size", "Frequency"])

# Expand the dataset (repeat sizes based on frequency)
expanded_sizes = []
for size, freq in zip(data["Size"], data["Frequency"]):
    expanded_sizes.extend([size] * freq)

# Create histogram
plt.hist(expanded_sizes, bins=30, color='blue', edgecolor='black', alpha=0.7)

# Labels and Title
plt.xlabel("Packet Size (bytes)")
plt.ylabel("Frequency")
plt.title("Packet Size Distribution (Histogram)")
plt.grid(axis="y", linestyle="--", alpha=0.7)

# Save the histogram as an image
plt.savefig("part1_histogram.png", dpi=300, bbox_inches="tight")

print("Histogram saved as part1_histogram.png")
