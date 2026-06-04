import csv
import os
from datetime import datetime


def save_device_event(
    event,
    ip,
    vendor
):

    os.makedirs(
        "reports",
        exist_ok=True
    )

    path = (
        "reports/device_events.csv"
    )

    file_exists = os.path.exists(
        path
    )

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
                    "TIME",
                    "EVENT",
                    "IP",
                    "VENDOR"
                ]
            )

        writer.writerow(
            [
                datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                event,
                ip,
                vendor
            ]
        )
