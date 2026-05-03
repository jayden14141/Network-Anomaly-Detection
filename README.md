# Network-Anomaly-Detection

## Project Description
 
 This project will involve creating a program that can monitor and track traffic over a chosen network, then capture and analyse this data to identify any security issues with the network.

## Requirements

1. Monitoring of data across a network
2. Intercepting and logging network data packets
3. Analysing this data to find any security issues
4. If possible, provide recommendations on improvements to the security of that network

### Packet Capture Specification
   - Sorting and filtering with specific parameters
     - e.g. protocol, source port, or IP version.
   - Reading and writing of PCAP files
   - Interactive GUI


## MVP Information
- Captures packets with Scapy
- Displays packets with interactive GUI (PyQt - Python GUI framework)
- Filtering and sorting functionality
- Saving and opening of pcap files
- Unit testing for packet capturing

## Beta Information
- Same as MVP
- Graphs of attributes of captured packets:
  - Protocol Frequency
  - IP Network Map
  - MAC Network Map
  - Source address frequency
- Two attack analysis methods:
  - TCP SYN Flood detection
  - ARP Spoof Detection
  
## Final Release Information
- Same as Beta
- Attack Analysis Methods:
  - TCP Scanning
  - DOS
  - ICMP Flood
  - HTTP Flood
  - DNS Flood

## Setup instruction for development
### Prerequisites

- Clone GitHub repository with the following command
```
git clone https://github.com/spe-uob/2022-NetworkTrafficAnalysis.git
```

#### Windows
- Download [Python](https://www.python.org/downloads/)  
- Check the python version with command (<3.9 recommended)
```
python --version
```

- Download Python libraries Scapy, Npcap, Pyqt5, MatPlotLib, pandas, and networkx with the command   
```
pip install Scapy
pip install Npcap
pip install Pyqt5
pip install matplotlib
pip install pandas  
pip install networkx
```
Or download [Scapy and Npcap](https://scapy.readthedocs.io/en/latest/installation.html) with this link


#### MacOS - Intel
- Download [Python](https://www.python.org/downloads/)

- Download library dependencies with the following command
```
pip install -r requirements.txt
```

#### MacOS - Arm64 (M1 / M2)
*The Scapy library is currently unavailable with local machine itself.*

- Download [Anaconda](https://www.anaconda.com/download/)

- Create a virtual enviroment
```
conda create -n <Environment name> python=<Version>
```
- Check if the environment is initialised
```
conda env list
```
- Activate the environment
```
activate <Environment name>
```
or
```
source activate <Environment name>
```

- Download library dependencies with the following command
```
pip install -r requirements.txt
```


_When finished running the program, don't forget to deactivate the virtual environment._
```
deactivate
```

## Deployment Instructions

- Run main.py with command
```
python code/pythonGUI/main.py
```

_(MacOS) When prompted to configure Python interpreter, select conda interpretor_

## Ethics
Participants(data) are not involved.

## License
Distributed under a [MIT License](https://github.com/spe-uob/2022-NetworkTrafficAnalysis/blob/cc94accefc228c9b78435800318bc0ce85b0b30c/LICENCE).

