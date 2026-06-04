import csv
import os
from datetime import datetime


def save_inventory(devices):

    os.makedirs(
        "reports",
        exist_ok=True
    )

    path = "reports/inventory.csv"

    existing_macs = set()

    if os.path.exists(path):

        with open(
            path,
            "r",
            encoding="utf-8"
        ) as file:

            reader = csv.DictReader(file)

            for row in reader:
                existing_macs.add(
                    row["MAC"]
                )

    file_exists = os.path.exists(path)

    with open(
        path,
        "a",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.writer(file)

        if not file_exists:

            writer.writerow(
                [
                    "IP",
                    "HOST",
                    "MAC",
                    "VENDOR",
                    "FIRST_SEEN"
                ]
            )

        for device in devices:

            if device["mac"] not in existing_macs:

                writer.writerow(
                    [
                        device["ip"],
                        device["hostname"],
                        device["mac"],
                        device.get("vendor", "Unknown"),
                        datetime.now().strftime(
                            "%Y-%m-%d %H:%M:%S"
                        )
                    ]
                )
