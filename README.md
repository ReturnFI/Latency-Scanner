
# TCP Latency Scanner

Simple multi-threaded TCP latency scanner with support for SNI (TLS) and CIDR ranges.


## Usage

### Scan single IP

```bash
python scanner.py --ip 1.1.1.1 --ports 443 --sni example.com --output results.txt
````

### Scan multiple IPs

```bash
python scanner.py --ip 1.1.1.1 8.8.8.8 --ports 80 443 --output results.txt
```

### Scan CIDR range

```bash
python scanner.py --ip 185.208.173.0/24 --ports 443 --sni cdn.example.com --output results.txt
```

### Load targets from file

```bash
python scanner.py --file targets.txt --ports 443 --sni example.com --output results.txt
```


## Options

* `--ip`       IP or CIDR
* `--file`     File with targets
* `--ports`    Ports to scan (required)
* `--sni`      Hostname for TLS / HTTP
* `--timeout`  Timeout (default: 2.0)
* `--retries`  Retry count (default: 3)
* `--workers`  Threads (default: 200)
* `--top`      Show top results (default: 10)
* `--output`   Output file (default: results.txt)

---

## Output

* Shows fastest hosts in terminal
* Saves results to `results.txt`



## Example

```bash
python scanner.py \
  --ip 185.208.173.0/24 \
  --ports 443 \
  --sni cdn.example.com \
  --workers 300
  --output results.txt
```

