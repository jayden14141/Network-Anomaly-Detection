## Setup instruction for development
### Prerequisites

- Clone GitHub repository with the following command
```
git clone https://github.com/spe-uob/2022-NetworkTrafficAnalysis.git
```

### Windows
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


### MacOS - Intel
- Download [Python](https://www.python.org/downloads/)

- Download library dependencies with the following command
```
pip install -r requirements.txt
```

### MacOS - Arm64 (M1 / M2)
*The Scapy library is currently unavailable with local machine itself.*

- Download [Anaconda](https://www.anaconda.com/download/)

- Create a virtual environment
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

_(macOS) When prompted to configure Python interpreter, select conda interpreter_



