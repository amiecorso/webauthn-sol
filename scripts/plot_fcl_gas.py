#!/usr/bin/env python3
import csv
import os
import argparse
import matplotlib.pyplot as plt

DEF_CSV = os.path.join(os.path.dirname(__file__), "../test/fixtures/fcl_gas_profile.csv")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default=DEF_CSV, help="Path to fcl_gas_profile.csv")
    ap.add_argument("--bins", type=int, default=30, help="Number of histogram bins")
    ap.add_argument("--out", default="fcl_gas_hist.png", help="Output image filename")
    args = ap.parse_args()

    gas_values = []
    with open(args.csv, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                gas_values.append(int(row["gas"]))
            except Exception:
                pass

    if not gas_values:
        print("No gas values found in CSV", args.csv)
        return

    plt.figure(figsize=(8, 5))
    plt.hist(gas_values, bins=args.bins, edgecolor="black")
    plt.xlabel("Gas used (verify)")
    plt.ylabel("Count")
    plt.title("FCL verify gas distribution")
    plt.tight_layout()
    plt.savefig(args.out, dpi=150)
    print("Saved", args.out)

if __name__ == "__main__":
    main()
