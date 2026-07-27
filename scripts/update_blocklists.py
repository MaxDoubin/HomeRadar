#!/usr/bin/env python3
"""Update configured blocklists without starting the web application."""
from backend.db import get_conn, init_db
from backend.dns.blocklists import record_update_results
from backend.services import blocklists


if __name__ == "__main__":
    init_db()
    results = blocklists.update()
    with get_conn() as connection:
        record_update_results(connection, results)
    for result in results:
        print(f"{result.status:5} {result.domain_count:8} {result.source}")
    print(f"active domains: {blocklists.count}")
