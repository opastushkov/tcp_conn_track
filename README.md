### Requirements
glibc
  ```sh
  sudo apt-get install libglib2.0-dev
  ```
pcap
  ```sh
  sudo apt-get install libpcap-dev
  ```

### Installation

1. Clone the repo.
  ```sh
  git clone git@github.com:opastushkov/tcp_conn_track.git
  ```
2. Run make.
  ```sh
  cd tcp_conn_track
  make
  ```
## Usage
```sh
Usage ./build/conn_track: [-i interface] [-f filename] [-d] [--help]
```
