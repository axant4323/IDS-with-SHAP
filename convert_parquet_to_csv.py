import pyarrow.parquet as pq
import pyarrow.csv as csv
import pyarrow as pa
import os

input_file = "input.parquet"
output_file = "output.csv"

parquet_file = pq.ParquetFile(input_file)

writer = None
total_rows = 0

for batch in parquet_file.iter_batches(batch_size=100_000):
    table = pa.Table.from_batches([batch])

    if writer is None:
        writer = csv.CSVWriter(output_file, table.schema)

    writer.write_table(table)

    total_rows += table.num_rows
    print(f"Converted {total_rows:,} rows...")

if writer:
    writer.close()

print(f"\nDone!")
print(f"Output: {output_file}")
print(f"Total rows: {total_rows:,}")
