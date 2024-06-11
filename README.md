# PExtract
There is a desperate need for a **Command-Line Windows** program for extracting features needed for training **Machine Learning** models for detecting 
*Malicious Software,* a niche that is becoming popular among the *Cyber-Security Researchers.* There is a number of great applications for *malware analysts* 
to dissect **Malware,** however those applications are *GUI-based* and hardly provide any help in **ML-based malware detection pipelines,** where 
everything should be automated.

***PExtract*** is a `C` library made to solve this very reason. 

# Installation
## Compile with Make
```sh
git clone https://github.com/AdiKsOnDev/PExtract.git
cd PExtract
make
```

## Compile with mingw32-make
```sh
git clone https://github.com/AdiKsOnDev/PExtract.git
cd PExtract
mingw32-make
```

# Usage
You can get all the applicable options by running:

```sh
pextract -h
```

The simplest use-case would be:

```sh
pextract -i <path/to/a/pefile>
```
