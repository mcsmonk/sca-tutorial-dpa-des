# sca-tutorial-dpa-des

This repository include some notebooks for DPA tutorial.

## Structure

```
├──── README.md
|
├──── dataset
|
├──── 1_data_io
|       ├── 1_data_io.tar.gz // {ipynb,html}
|       ├── README.md
|       ├── ...
|
├──── 2_dpa_des_simulation
|       ├── 2_dpa_des_simulation.tar.gz // {ipynb,html}
|       ├── README.md
|       ├── ...
|
├──── 3_dpa_des_sw
|       ├── 3_dpa_des_sw.tar.gz // {ipynb,html}
|       ├── README.md
|       ├── ...
|
├──── 4_dpa_des_hw
|       ├── 4_dpa_des_hw.tar.gz // {ipynb,html}
|       ├── README.md
|       ├── ...
|
```

## Environment
- python
  ```pip install numpy scipy tqdm h5py matplotlib bokeh```
- 

## Data
All data must be in 'dataset' directory
1. DES SW
    - avrcryptolib
      - des.c \[[link](https://github.com/newaetech/chipwhisperer/blob/develop/hardware/victims/firmware/crypto/avrcryptolib/des/des.c)\]
    - trace \[[hdf5](https://www.dropbox.com/s/atq3tihqzs0sij2/220423_jinsunghyun_cw-xmega-des-5MHz-50MS-10ppc-N5000-comp1ppc--2022.04.07-18.50.58.h5?dl=0)\]
2. DES HW
   - DPA Contest v1 \[[link](https://www.dpacontest.org/index.php)\]
   - trace
     - secmatv1_2006_04_0809 \[[Bin](https://www.dropbox.com/s/ca5i035woqhawkn/secmatv1_2006_04_0809.zip?dl=0)\]\[[mat](https://www.dropbox.com/s/ye2o0h7c2jo470k/secmatv1_2006_04_0809.mat?dl=0)\]\[[hdf5](https://www.dropbox.com/s/d3be01gv4elpkqy/secmatv1_2006_04_0809.h5?dl=0)\]
     - secmatv3_20070924_des
     - secmatv3_20071219_des

## Reference
- \[paper\] Differential Power Analysis \[[https://doi.org/10.1007/3-540-48405-1_25](https://doi.org/10.1007/3-540-48405-1_25)\]
- \[book\] Power Analysis Attacks: Revealing the Secrets of Smart Cards \[[https://doi.org/10.1007/978-0-387-38162-6](https://doi.org/10.1007/978-0-387-38162-6)\]


## Author

Sunghyun Jin (sunghyunjin@korea.ac.kr, [https://sunghyunjin.com](https://sunghyunjin.com))

Cryptographic Algorithm Lab.

School of Cyber Security,
Korea University,
Republic of Korea

Center for Information Security Technologies (CIST),
Institute of Cyber Security & Privacy (ICSP),
Korea University,
Republic of Korea
